import base64

from twisted.internet.defer import inlineCallbacks
from twisted.internet.error import DNSLookupError, ConnectionRefusedError
from twisted.web.error import SchemeNotSupported

from vumi.application import ApplicationWorker
from vumi.config import ConfigBool, ConfigInt, ConfigText
from vumi.utils import http_request_full, HttpTimeoutError
from vumi import log

from .utils import extract_auth_from_url


class VumiApiWorkerConfig(ApplicationWorker.CONFIG_CLASS):
    """ Configuration options for the Vumi API Worker """
    conversation_key = ConfigText(
        "Conversation key for the current conversation")
    push_message_url = ConfigText(
        "URL for messages to be send to")
    ignore_messages = ConfigBool(
        "If True, no messages will be sent to the push_message_url",
        default=False)
    timeout = ConfigInt(
        "How long to wait for a response from a server when posting "
        "messages or events", default=5)


class VumiApiWorker(ApplicationWorker):
    CONFIG_CLASS = VumiApiWorkerConfig

    def setup_application(self):
        # TODO Start HTTP server
        pass

    def teardown_application(self):
        pass

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
        config = yield self.get_static_config()
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

    def consume_event(self, event):
        # TODO: Event handling
        pass

    def consume_ack(self, event):
        return self.consume_event(event)

    def consume_nack(self, event):
        return self.consume_event(event)

    def consume_delivery_report(self, event):
        return self.consume_event(event)

    def consume_unknown_event(self, event):
        return self.consume_event(event)
