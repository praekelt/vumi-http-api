from twisted.internet.defer import inlineCallbacks

from vumi.application.tests.helpers import ApplicationHelper
from vumi.tests.helpers import VumiTestCase

from vumi_http_api import VumiApiWorker


class TestVumiApiWorker(VumiTestCase):
    @inlineCallbacks
    def setUp(self):
        self.app_helper = yield self.add_helper(
            ApplicationHelper(VumiApiWorker))
        self.worker = yield self.app_helper.get_application({})

    @inlineCallbacks
    def test_ack_event(self):
        event = self.app_helper.make_ack()
        yield self.app_helper.dispatch_event(event)

    @inlineCallbacks
    def test_nack_event(self):
        event = self.app_helper.make_nack()
        yield self.app_helper.dispatch_event(event)

    @inlineCallbacks
    def test_unknown_event(self):
        # temporarily pretend the worker doesn't know about acks
        del self.worker._event_handlers['ack']
        event = self.app_helper.make_ack()
        yield self.app_helper.dispatch_event(event)

    @inlineCallbacks
    def test_delivery_report(self):
        event = self.app_helper.make_delivery_report()
        yield self.app_helper.dispatch_event(event)

    @inlineCallbacks
    def test_user_message(self):
        message = self.app_helper.make_inbound('foo')
        yield self.app_helper.dispatch_inbound(message)
