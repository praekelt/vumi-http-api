import base64
import logging

from twisted.internet.defer import inlineCallbacks, DeferredQueue
from twisted.internet.error import DNSLookupError, ConnectionRefusedError
from twisted.web.error import SchemeNotSupported
from twisted.web.server import NOT_DONE_YET

from urlparse import urlparse, urlunparse

from vumi.application.tests.helpers import ApplicationHelper
from vumi.message import TransportEvent, TransportUserMessage
from vumi.tests.helpers import VumiTestCase
from vumi.tests.utils import LogCatcher, MockHttpServer
from vumi.utils import HttpTimeoutError

from vumi_http_api import VumiApiWorker


class TestVumiApiWorkerBase(VumiTestCase):

    @inlineCallbacks
    def setUp(self):
        self.app_helper = yield self.add_helper(
            ApplicationHelper(VumiApiWorker))

    @inlineCallbacks
    def start_app_worker(self, config_overrides={}):
        # Mock server to test HTTP posting of inbound messages & events
        self.mock_push_server = MockHttpServer(self.handle_request)
        yield self.mock_push_server.start()
        self.add_cleanup(self.mock_push_server.stop)
        self.push_calls = DeferredQueue()

        self.config = {
            'conversation_key': 'key_conversation',
            'push_message_url': self.get_message_url(),
            'push_event_url': self.get_event_url(),
        }
        self.config.update(config_overrides)
        self.app = yield self.app_helper.get_application(self.config)
        self.conversation = self.config['conversation_key']

    def get_message_url(self):
        return self.mock_push_server.url

    def get_event_url(self):
        return self.mock_push_server.url

    def handle_request(self, request):
        self.push_calls.put(request)
        return NOT_DONE_YET


class TestVumiApiWorker(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_post_inbound_message(self):
        yield self.start_app_worker()
        msg_d = self.app_helper.make_dispatch_inbound(
            'in 1', message_id='1', conv=self.conversation)

        req = yield self.push_calls.get()
        posted_json = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        msg = yield msg_d

        posted_msg = TransportUserMessage.from_json(posted_json)
        self.assertEqual(posted_msg['message_id'], msg['message_id'])

    @inlineCallbacks
    def test_post_inbound_message_ignored(self):
        yield self.start_app_worker({
            'ignore_messages': True
        })

        yield self.app_helper.make_dispatch_inbound(
            'in 1', message_id='1', conv=self.conversation)
        self.push_calls.put(None)
        req = yield self.push_calls.get()
        self.assertEqual(req, None)

    @inlineCallbacks
    def test_post_inbound_message_201_response(self):
        yield self.start_app_worker()
        with LogCatcher(message='Got unexpected response code') as lc:
            msg_d = self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            req = yield self.push_calls.get()
            req.setResponseCode(201)
            req.finish()
            yield msg_d
        self.assertEqual(lc.messages(), [])

    @inlineCallbacks
    def test_post_inbound_message_500_response(self):
        yield self.start_app_worker()
        with LogCatcher(message='Got unexpected response code') as lc:
            msg_d = self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            req = yield self.push_calls.get()
            req.setResponseCode(500)
            req.finish()
            yield msg_d
        [warning_log] = lc.messages()
        self.assertTrue(self.get_message_url() in warning_log)
        self.assertTrue('500' in warning_log)

    @inlineCallbacks
    def test_post_inbound_message_no_url(self):
        yield self.start_app_worker({
            'push_message_url': None
        })

        msg_prefix = 'push_message_url not configured'
        with LogCatcher(message=msg_prefix, log_level=logging.WARNING) as lc:
            yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [url_not_configured_log] = lc.messages()
        self.assertTrue(self.conversation in url_not_configured_log)

    def _patch_http_request_full(self, exception_class):
        from vumi_http_api import vumi_api

        def raiser(*args, **kw):
            raise exception_class()
        self.patch(vumi_api, 'http_request_full', raiser)

    @inlineCallbacks
    def test_post_inbound_message_unsupported_scheme(self):
        yield self.start_app_worker({
            'push_message_url': 'example.com',
        })

        self._patch_http_request_full(SchemeNotSupported)
        with LogCatcher(message='Unsupported') as lc:
            yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [unsupported_scheme_log] = lc.messages()
        self.assertTrue('example.com' in unsupported_scheme_log)

    @inlineCallbacks
    def test_post_inbound_message_timeout(self):
        yield self.start_app_worker()
        self._patch_http_request_full(HttpTimeoutError)
        with LogCatcher(message='Timeout') as lc:
            yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [timeout_log] = lc.messages()
        self.assertTrue(self.mock_push_server.url in timeout_log)

    @inlineCallbacks
    def test_post_inbound_message_dns_lookup_error(self):
        yield self.start_app_worker()
        self._patch_http_request_full(DNSLookupError)
        with LogCatcher(message='DNS lookup error') as lc:
            yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [dns_log] = lc.messages()
        self.assertTrue(self.mock_push_server.url in dns_log)

    @inlineCallbacks
    def test_post_inbound_message_connection_refused_error(self):
        yield self.start_app_worker()
        self._patch_http_request_full(ConnectionRefusedError)
        with LogCatcher(message='Connection refused') as lc:
            yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [conn_refused_log] = lc.messages()
        self.assertTrue(self.mock_push_server.url in conn_refused_log)

    @inlineCallbacks
    def test_post_inbound_message_no_conversation_defined(self):
        yield self.start_app_worker({
            'conversation_key': None,
        })

        self._patch_http_request_full(ConnectionRefusedError)
        with LogCatcher(message='Cannot find conversation') as lc:
            msg = yield self.app_helper.make_dispatch_inbound(
                'in 1', message_id='1', conv=self.conversation)
            [noconv_log] = lc.messages()
        self.assertTrue(msg['message_id'] in noconv_log)

    def make_outbound(self, conv, content, **kw):
        return self.app_helper.make_outbound(content, conv=conv, **kw)

    @inlineCallbacks
    def test_post_ack_event(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        event_d = self.app_helper.make_dispatch_ack(
            msg1, conv=self.conversation)
        req = yield self.push_calls.get()
        posted_json_data = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        ack1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), ack1)

    @inlineCallbacks
    def test_post_nack_event(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        event_d = self.app_helper.make_dispatch_nack(
            msg1, conv=self.conversation)
        req = yield self.push_calls.get()
        posted_json_data = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        ack1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), ack1)

    @inlineCallbacks
    def test_post_unknown_event(self):
        yield self.start_app_worker()
        # temporarily pretend the worker doesn't know about acks
        del self.app._event_handlers['ack']
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        event_d = self.app_helper.make_dispatch_ack(
            msg1, conv=self.conversation)
        req = yield self.push_calls.get()
        posted_json_data = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        ack1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), ack1)

    @inlineCallbacks
    def test_post_delivery_report(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        event_d = self.app_helper.make_dispatch_delivery_report(
            msg1, conv=self.conversation)
        req = yield self.push_calls.get()
        posted_json_data = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        ack1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), ack1)

    @inlineCallbacks
    def test_post_inbound_event(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        event_d = self.app_helper.make_dispatch_ack(
            msg1, conv=self.conversation)

        req = yield self.push_calls.get()
        posted_json_data = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        ack1 = yield event_d

        self.assertEqual(TransportEvent.from_json(posted_json_data), ack1)

    @inlineCallbacks
    def test_post_inbound_event_ignored(self):
        yield self.start_app_worker({
            'ignore_events': True,
        })

        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')
        yield self.app_helper.make_dispatch_ack(
            msg1, conv=self.conversation)
        self.push_calls.put(None)
        req = yield self.push_calls.get()
        self.assertEqual(req, None)

    @inlineCallbacks
    def test_post_inbound_event_no_url(self):
        yield self.start_app_worker({
            'push_event_url': None,
        })

        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')

        msg_prefix = 'push_event_url not configured'
        with LogCatcher(message=msg_prefix, log_level=logging.INFO) as lc:
            yield self.app_helper.make_dispatch_ack(
                msg1, conv=self.conversation)
            [url_not_configured_log] = lc.messages()
        self.assertTrue(self.conversation in url_not_configured_log)

    @inlineCallbacks
    def test_post_inbound_event_timeout(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')

        self._patch_http_request_full(HttpTimeoutError)
        with LogCatcher(message='Timeout') as lc:
            yield self.app_helper.make_dispatch_ack(
                msg1, conv=self.conversation)
            [timeout_log] = lc.messages()
        self.assertTrue(timeout_log.endswith(self.mock_push_server.url))

    @inlineCallbacks
    def test_post_inbound_event_dns_lookup_error(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')

        self._patch_http_request_full(DNSLookupError)
        with LogCatcher(message='DNS lookup error') as lc:
            yield self.app_helper.make_dispatch_ack(
                msg1, conv=self.conversation)
            [dns_log] = lc.messages()
        self.assertTrue(self.mock_push_server.url in dns_log)

    @inlineCallbacks
    def test_post_inbound_event_connection_refused_error(self):
        yield self.start_app_worker()
        msg1 = yield self.make_outbound(
            self.conversation, 'out 1', message_id='1')

        self._patch_http_request_full(ConnectionRefusedError)
        with LogCatcher(message='Connection refused') as lc:
            yield self.app_helper.make_dispatch_ack(
                msg1, conv=self.conversation)
            [dns_log] = lc.messages()
        self.assertTrue(self.mock_push_server.url in dns_log)


class TestVumiApiWorkerWithAuth(TestVumiApiWorkerBase):
    @inlineCallbacks
    def test_push_with_basic_auth(self):
        def get_message_url():
            parse_result = urlparse(self.mock_push_server.url)
            return urlunparse((
                parse_result.scheme,
                'username:password@%s:%s' % (
                    parse_result.hostname, parse_result.port),
                parse_result.path,
                parse_result.params,
                parse_result.query,
                parse_result.fragment))
        self.get_message_url = get_message_url

        yield self.start_app_worker()
        self.app_helper.make_dispatch_inbound(
            'in', message_id='1', conv=self.conversation)
        req = yield self.push_calls.get()
        req.finish()
        [header] = req.requestHeaders.getRawHeaders('Authorization')
        self.assertEqual(
            header, 'Basic %s' % (base64.b64encode('username:password')))

    @inlineCallbacks
    def test_push_with_basic_auth_username_only(self):
        def get_message_url():
            parse_result = urlparse(self.mock_push_server.url)
            return urlunparse((
                parse_result.scheme,
                'username@%s:%s' % (
                    parse_result.hostname, parse_result.port),
                parse_result.path,
                parse_result.params,
                parse_result.query,
                parse_result.fragment))
        self.get_message_url = get_message_url

        yield self.start_app_worker()
        self.app_helper.make_dispatch_inbound(
            'in', message_id='1', conv=self.conversation)
        req = yield self.push_calls.get()
        req.finish()
        [header] = req.requestHeaders.getRawHeaders('Authorization')
        self.assertEqual(
            header, 'Basic %s' % (base64.b64encode('username:')))
