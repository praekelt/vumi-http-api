from twisted.web import resource
from vumi.tests.helpers import VumiTestCase

from vumi_http_api.auth import ConversationRealm


class TestCoversationRealm(VumiTestCase):
    def test_non_web_resource_interface(self):
        r = resource.Resource()
        cr = ConversationRealm(r)
        self.assertRaises(
            NotImplementedError, cr.requestAvatar, None, None, None)
