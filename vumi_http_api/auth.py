from zope.interface import implements

from twisted.cred import portal, checkers, credentials, error
from twisted.web import resource
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory


class ConversationRealm(object):
    implements(portal.IRealm)

    def __init__(self, resource):
        self.resource = resource

    def requestAvatar(self, user, mind, *interfaces):
        if resource.IResource in interfaces:
            return (resource.IResource, self.resource, lambda: None)
        raise NotImplementedError()


class ConversationAccessChecker(object):
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, worker, conversation_key):
        self.worker = worker
        self.conversation_key = conversation_key

    def requestAvatarId(self, credentials):
        username = credentials.username
        token = credentials.password
        tokens = self.worker.get_static_config().api_tokens
        valid_tokens = [t for t in tokens if t['account'] == username]
        valid_tokens = [
            t for t in tokens if
            t['conversation'] == self.conversation_key]
        if len(valid_tokens) > 0:
            valid_tokens = valid_tokens[0]['tokens']
            if token in valid_tokens:
                return username
        raise error.UnauthorizedLogin()


class AuthorizedResource(resource.Resource):

    def __init__(self, worker, resource_class):
        resource.Resource.__init__(self)
        self.worker = worker
        self.resource_class = resource_class

    def render(self, request):
        return resource.NoResource().render(request)

    def getChild(self, conversation_key, request):
        if conversation_key:
            res = self.resource_class(self.worker, conversation_key)
            checker = ConversationAccessChecker(self.worker, conversation_key)
            realm = ConversationRealm(res)
            p = portal.Portal(realm, [checker])

            factory = BasicCredentialFactory("Conversation Realm")
            protected_resource = HTTPAuthSessionWrapper(p, [factory])

            return protected_resource
        else:
            return resource.NoResource()
