import base64
import json
import logging

from twisted.internet.defer import inlineCallbacks, DeferredQueue
from twisted.internet.error import DNSLookupError, ConnectionRefusedError
from twisted.web.error import SchemeNotSupported
from twisted.web.server import NOT_DONE_YET
from twisted.web import http

from urlparse import urlparse, urlunparse

from vumi.application.tests.helpers import ApplicationHelper
from vumi.config import ConfigError
from vumi.message import TransportEvent, TransportUserMessage
from vumi.tests.helpers import VumiTestCase
from vumi.tests.utils import LogCatcher, MockHttpServer
from vumi.utils import http_request_full, HttpTimeoutError

from vumi_http_api import VumiApiWorker
from vumi_http_api.vumi_api import ConfigTokens


class FakeModel(object):
    def __init__(self, config):
        self._config_data = config


class TestConfigTokens(VumiTestCase):

    def fake_model(self, *value, **kw):
        config = kw.pop('config', {})
        if value:
            assert len(value) == 1
            config['foo'] = value[0]
        return FakeModel(config)

    def assert_field_valid(self, field, *value, **kw):
        field.validate(self.fake_model(*value, **kw))

    def assert_field_invalid(self, field, *value, **kw):
        self.assertRaises(ConfigError, field.validate,
                          self.fake_model(*value, **kw))

    def make_field(self, field_cls, **kw):
        field = field_cls("desc", **kw)
        field.setup('foo')
        return field

    def test_config_token_not_dict(self):
        field = self.make_field(ConfigTokens)
        self.assert_field_invalid(field, [[]])

    def test_config_missing_key(self):
        field = self.make_field(ConfigTokens)
        self.assert_field_invalid(
            field, [{'account': '', 'conversation': ''}])
        self.assert_field_invalid(
            field, [{'account': '', 'tokens': ''}])
        self.assert_field_invalid(
            field, [{'tokens': '', 'conversation': ''}])
        self.assert_field_invalid(
            field, [{}])

    def test_config_token_tuple(self):
        field = self.make_field(ConfigTokens)
        self.assert_field_valid(
            field, [{'account': '', 'conversation': '', 'tokens': ('a', 'b')}])

    def test_config_token_not_list(self):
        field = self.make_field(ConfigTokens)
        self.assert_field_invalid(
            field, [{'account': '', 'conversation': '', 'tokens': ''}])


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
            'health_path': '/health/',
            'web_path': '/foo',
            'web_port': 0,
            'api_tokens': [{
                'account': 'account_key',
                'conversation': 'key_conversation',
                'tokens': ['token-1', 'token-2', 'token-3'],
            }, ]
        }
        self.config.update(config_overrides)
        self.app = yield self.app_helper.get_application(self.config)
        self.conversation = self.config['conversation_key']
        self.addr = self.app.webserver.getHost()
        self.url = 'http://%s:%s%s' % (
            self.addr.host, self.addr.port, self.config['web_path'])
        self.auth_headers = {
            'Authorization': ['Basic ' + base64.b64encode('%s:%s' % (
                'account_key', 'token-1'))],
        }

    def get_message_url(self):
        return self.mock_push_server.url

    def get_event_url(self):
        return self.mock_push_server.url

    def handle_request(self, request):
        self.push_calls.put(request)
        return NOT_DONE_YET

    def assert_bad_request(self, response, reason):
        self.assertEqual(response.code, http.BAD_REQUEST)
        self.assertEqual(
            response.headers.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        data = json.loads(response.delivered_body)
        self.assertEqual(data, {
            "success": False,
            "reason": reason,
        })

    def _patch_http_request_full(self, exception_class):
        from vumi_http_api import vumi_api

        def raiser(*args, **kw):
            raise exception_class()
        self.patch(vumi_api, 'http_request_full', raiser)


class TestVumiApiWorkerSendToEndpoint(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_send_to(self):
        yield self.start_app_worker()
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'helper_metadata': {'foo': 'bar'},
            'session_event': 'new',
            'message_id': 'evil_id',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')

        self.assertEqual(response.code, http.OK)
        self.assertEqual(
            response.headers.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        put_msg = json.loads(response.delivered_body)

        [sent_msg] = self.app_helper.get_dispatched_outbound()
        self.assertEqual(sent_msg['to_addr'], sent_msg['to_addr'])
        # We do not respect the message_id that's been given.
        self.assertNotEqual(sent_msg['message_id'], msg['message_id'])
        self.assertEqual(sent_msg['message_id'], put_msg['message_id'])
        self.assertEqual(sent_msg['to_addr'], msg['to_addr'])
        self.assertEqual(sent_msg['from_addr'], None)
        self.assertEqual(sent_msg['session_event'], 'new')
        self.assertEqual(sent_msg['helper_metadata'], {'foo': 'bar'})

    @inlineCallbacks
    def test_send_to_with_zero_worker_concurrency(self):
        """
        When the worker_concurrency_limit is set to zero, our requests will
        never complete.

        This is a hacky way to test that the concurrency limit is being applied
        without invasive changes to the app worker.
        """
        yield self.start_app_worker({'worker_concurrency_limit': 0})
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'message_id': 'evil_id',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        d = http_request_full(
            url, json.dumps(msg), self.auth_headers, method='PUT',
            timeout=0.2)

        yield self.assertFailure(d, HttpTimeoutError)

    @inlineCallbacks
    def test_send_to_within_content_length_limit(self):
        yield self.start_app_worker({
            'content_length_limit': 182,
        })

        msg = {
            'content': 'foo',
            'to_addr': '+1234',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')
        self.assertEqual(
            response.headers.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        put_msg = json.loads(response.delivered_body)
        self.assertEqual(response.code, http.OK)

        [sent_msg] = self.app_helper.get_dispatched_outbound()
        self.assertEqual(sent_msg['to_addr'], put_msg['to_addr'])
        self.assertEqual(sent_msg['message_id'], put_msg['message_id'])
        self.assertEqual(sent_msg['session_event'], None)
        self.assertEqual(sent_msg['to_addr'], '+1234')
        self.assertEqual(sent_msg['from_addr'], None)

    @inlineCallbacks
    def test_send_to_content_too_long(self):
        yield self.start_app_worker({
            'content_length_limit': 10,
        })

        msg = {
            'content': "This message is longer than 10 characters.",
            'to_addr': '+1234',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(
            url, json.dumps(msg), self.auth_headers, method='PUT')
        self.assert_bad_request(
            response, "Payload content too long: 42 > 10")

    @inlineCallbacks
    def test_send_to_with_evil_content(self):
        yield self.start_app_worker()
        msg = {
            'content': 0xBAD,
            'to_addr': '+1234',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')
        self.assert_bad_request(
            response, "Invalid or missing value for payload key 'content'")

    @inlineCallbacks
    def test_send_to_with_evil_to_addr(self):
        yield self.start_app_worker()
        msg = {
            'content': 'good',
            'to_addr': 1234,
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')
        self.assert_bad_request(
            response, "Invalid or missing value for payload key 'to_addr'")


class TestVumiApiWorkerHealthEndpoint(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_health_response(self):
        yield self.start_app_worker()
        health_url = 'http://%s:%s%s' % (
            self.addr.host, self.addr.port, self.config['health_path'])

        response = yield http_request_full(health_url, method='GET')
        self.assertEqual(response.delivered_body, 'OK')


class TestVumiApiWorkerPushMessages(TestVumiApiWorkerBase):

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
    def test_post_inbound_message_new_session(self):
        yield self.start_app_worker()
        msg_d = self.app_helper.make_dispatch_inbound(
            'in 1', message_id='1', conv=self.conversation,
            session_event=TransportUserMessage.SESSION_NEW)

        req = yield self.push_calls.get()
        posted_json = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        msg = yield msg_d

        posted_msg = TransportUserMessage.from_json(posted_json)
        self.assertEqual(posted_msg['message_id'], msg['message_id'])
        self.assertEqual(
            posted_msg['session_event'], TransportUserMessage.SESSION_NEW)

    @inlineCallbacks
    def test_post_inbound_message_close_session(self):
        yield self.start_app_worker()
        msg_d = self.app_helper.make_dispatch_inbound(
            'in 1', message_id='1', conv=self.conversation,
            session_event=TransportUserMessage.SESSION_CLOSE)

        req = yield self.push_calls.get()
        posted_json = req.content.read()
        self.assertEqual(
            req.requestHeaders.getRawHeaders('content-type'),
            ['application/json; charset=utf-8'])
        req.finish()
        msg = yield msg_d

        posted_msg = TransportUserMessage.from_json(posted_json)
        self.assertEqual(posted_msg['message_id'], msg['message_id'])
        self.assertEqual(
            posted_msg['session_event'], TransportUserMessage.SESSION_CLOSE)

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


class TestVumiApiWorkerPushEvents(TestVumiApiWorkerBase):

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
        nack1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), nack1)

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
        dr1 = yield event_d
        self.assertEqual(TransportEvent.from_json(posted_json_data), dr1)

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


class TestVumiApiWorkerEndpoints(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_bad_urls(self):
        def assert_not_found(url, headers={}):
            d = http_request_full(url, method='GET', headers=headers)
            d.addCallback(lambda r: self.assertEqual(r.code, http.NOT_FOUND))
            return d

        yield self.start_app_worker()

        yield assert_not_found(self.url)
        yield assert_not_found(self.url + '/')
        yield assert_not_found('%s/%s' % (self.url, self.conversation),
                               headers=self.auth_headers)
        yield assert_not_found('%s/%s/' % (self.url, self.conversation),
                               headers=self.auth_headers)
        yield assert_not_found('%s/%s/foo' % (self.url, self.conversation),
                               headers=self.auth_headers)


class TestVumiApiWorkerConcurrency(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_concurrency_limit(self):
        yield self.start_app_worker({
            'concurrency_limit': 0,
        })
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'message_id': 'evil_id',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')

        self.assertEqual(response.code, http.FORBIDDEN)
        self.assertTrue(
            "Too many concurrent connections" in response.delivered_body)

    @inlineCallbacks
    def test_no_concurrency_limit(self):
        yield self.start_app_worker({
            'concurrency_limit': -1,
        })
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'message_id': 'evil_id',
        }

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(url, json.dumps(msg),
                                           self.auth_headers, method='PUT')

        self.assertEqual(response.code, http.OK)


class TestVumiApiWorker(TestVumiApiWorkerBase):

    @inlineCallbacks
    def test_put_bad_json(self):
        yield self.start_app_worker()
        msg = '{'

        url = '%s/%s/messages.json' % (self.url, self.conversation)
        response = yield http_request_full(
            url, msg, self.auth_headers, method='PUT')

        self.assertEqual(response.code, http.BAD_REQUEST)
        resp = json.loads(response.delivered_body)
        self.assertEqual(resp['reason'], 'Invalid Message')
        self.assertEqual(resp['success'], False)


class TestVumiApiWorkerAuth(TestVumiApiWorkerBase):

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

    @inlineCallbacks
    def test_missing_auth(self):
        yield self.start_app_worker()
        url = '%s/%s/messages.json' % (self.url, self.conversation)
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'message_id': 'evil_id',
        }
        response = yield http_request_full(url, json.dumps(msg), {},
                                           method='PUT')
        self.assertEqual(response.code, http.UNAUTHORIZED)
        self.assertEqual(response.headers.getRawHeaders('www-authenticate'), [
            'basic realm="Conversation Realm"'])

    @inlineCallbacks
    def test_invalid_auth(self):
        yield self.start_app_worker()
        url = '%s/%s/messages.json' % (self.url, self.conversation)
        msg = {
            'to_addr': '+2345',
            'content': 'foo',
            'message_id': 'evil_id',
        }
        auth_headers = {
            'Authorization': ['Basic %s' % (base64.b64encode('foo:bar'),)],
        }
        response = yield http_request_full(url, json.dumps(msg), auth_headers,
                                           method='PUT')
        self.assertEqual(response.code, http.UNAUTHORIZED)
        self.assertEqual(response.headers.getRawHeaders('www-authenticate'), [
            'basic realm="Conversation Realm"'])
