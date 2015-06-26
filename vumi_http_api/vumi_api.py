import base64

from copy import deepcopy

from twisted.internet.defer import inlineCallbacks
from twisted.internet.error import DNSLookupError, ConnectionRefusedError
from twisted.web.error import SchemeNotSupported

from vumi.application import ApplicationWorker
from vumi.config import (
    ConfigBool, ConfigDict, ConfigInt, ConfigList, ConfigText)
from vumi.persist.txredis_manager import TxRedisManager
from vumi.transports.httprpc import httprpc
from vumi.utils import http_request_full, HttpTimeoutError
from vumi import log

from .auth import AuthorizedResource
from .resource import ConversationResource
from .utils import extract_auth_from_url
from .concurrency_limiter import ConcurrencyLimitManager


class ConfigTokens(ConfigList):
    """A list of access tokens in the following format:

    tokens:
      -
        account: key
        conversation: conv_key
        tokens: [token11, token12, token13]
      -
        account: key2
        conversation: conv_key2
        tokens: [token21, token22]
    ...
    """
    field_type = 'list'

    def clean(self, value):
        value = super(ConfigTokens, self).clean(value)
        for token in value:
            if not isinstance(token, dict):
                self.raise_config_error("item %r is not a dict." % token)
            for key in ['account', 'conversation', 'tokens']:
                if key not in token:
                    self.raise_config_error(
                        "item %r doesn't contain %s key." % (token, key))
            if isinstance(token['tokens'], tuple):
                token['tokens'] = list(token['tokens'])
            if not isinstance(token['tokens'], list):
                self.raise_config_error(
                    "token list %r is not a list" % token['tokens'])
        return deepcopy(value)


class VumiApiWorkerConfig(ApplicationWorker.CONFIG_CLASS):
    """ Configuration options for the Vumi API Worker """
    conversation_key = ConfigText(
        "Conversation key for the current conversation")
    push_message_url = ConfigText(
        "URL for messages to be send to")
    push_event_url = ConfigText(
        "URL for events to be send to")
    ignore_messages = ConfigBool(
        "If True, no messages will be sent to the push_message_url",
        default=False)
    ignore_events = ConfigBool(
        "If True, no events will be sent to the push_message_url",
        default=False)
    timeout = ConfigInt(
        "How long to wait for a response from a server when posting "
        "messages or events", default=5)
    web_path = ConfigText(
        "The path the HTTP worker should expose the API on.",
        required=True, static=True)
    web_port = ConfigInt(
        "The port the HTTP worker should open for the API.",
        required=True, static=True)
    health_path = ConfigText(
        "The path the resource should receive health checks on.",
        default='/health/', static=True)
    concurrency_limit = ConfigInt(
        "Maximum number of clients per account. A value less than "
        "zero disables the limit.",
        default=10)
    worker_concurrency_limit = ConfigInt(
        "Maximum number of clients per account per worker. A value less than "
        "zero disables the limit. (Unlike concurrency_limit, this queues "
        "requests instead of rejecting them.)",
        default=1, static=True)
    redis_manager = ConfigDict("Redis config.", required=True, static=True)
    api_tokens = ConfigTokens(
        "A list of valid authentication tokens.", required=True, static=True)
    content_length_limit = ConfigInt(
        'Optional content length limit. If set, messages with content longer'
        'than this will be rejected.', required=False, static=True)


class VumiApiWorker(ApplicationWorker):
    CONFIG_CLASS = VumiApiWorkerConfig

    @inlineCallbacks
    def setup_application(self):
        config = self.get_static_config()
        self.web_path = config.web_path
        self.web_port = config.web_port
        self.health_path = config.health_path

        self.concurrency_limiter = ConcurrencyLimitManager(
            config.worker_concurrency_limit)
        self.webserver = self.start_web_resources([
            (self.get_conversation_resource(), self.web_path),
            (httprpc.HttpRpcHealthResource(self), self.health_path),
        ], self.web_port)
        self.redis = yield TxRedisManager.from_config(config.redis_manager)

    def get_conversation_resource(self):
        return AuthorizedResource(self, ConversationResource)

    @inlineCallbacks
    def teardown_application(self):
        yield self.webserver.loseConnection()

    def new_session(self, message):
        return self.consume_user_message(message)

    def close_session(self, message):
        return self.consume_user_message(message)

    @inlineCallbacks
    def consume_user_message(self, message):
        config = yield self.get_config(message)
        conversation = config.conversation_key
        if conversation is None:
            log.warning("Cannot find conversation for message: %r" % (
                message,))
            return
        ignore = config.ignore_messages
        if not ignore:
            push_url = config.push_message_url
            yield self.send_message_to_client(message, conversation, push_url)

    def send_message_to_client(self, message, conversation, push_url):
        if push_url is None:
            log.warning(
                "push_message_url not configured for conversation: %s" % (
                    conversation))
            return
        return self.push(push_url, message)

    @inlineCallbacks
    def push(self, url, vumi_message):
        config = yield self.get_config(vumi_message)
        data = vumi_message.to_json().encode('utf-8')
        try:
            auth, url = extract_auth_from_url(url.encode('utf-8'))
            headers = {
                'Content-Type': 'application/json; charset=utf-8',
            }
            if auth is not None:
                username, password = auth

                if password is None:
                    password = ''

                headers.update({
                    'Authorization': 'Basic %s' % (
                        base64.b64encode('%s:%s' % (username, password)),)
                })
            resp = yield http_request_full(
                url, data=data, headers=headers, timeout=config.timeout)
            if not (200 <= resp.code < 300):
                # We didn't get a 2xx response.
                log.warning('Got unexpected response code %s from %s' % (
                    resp.code, url))
        except SchemeNotSupported:
            log.warning('Unsupported scheme for URL: %s' % (url,))
        except HttpTimeoutError:
            log.warning("Timeout pushing message to %s" % (url,))
        except DNSLookupError:
            log.warning("DNS lookup error pushing message to %s" % (url,))
        except ConnectionRefusedError:
            log.warning("Connection refused pushing message to %s" % (url,))

    @inlineCallbacks
    def consume_event(self, event):
        config = yield self.get_config(event)
        conversation = config.conversation_key
        ignore = config.ignore_events
        if not ignore:
            push_url = config.push_event_url
            yield self.send_event_to_client(event, conversation, push_url)

    def send_event_to_client(self, event, conversation, push_url):
        if push_url is None:
            log.info(
                "push_event_url not configured for conversation: %s" % (
                    conversation))
            return
        return self.push(push_url, event)

    def consume_ack(self, event):
        return self.consume_event(event)

    def consume_nack(self, event):
        return self.consume_event(event)

    def consume_delivery_report(self, event):
        return self.consume_event(event)

    def consume_unknown_event(self, event):
        return self.consume_event(event)

    def get_health_response(self):
        return "OK"
