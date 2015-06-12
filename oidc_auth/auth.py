from .utils import log, get_user_model
from .models import OpenIDUser


class OpenIDConnectBackend(object):
    supports_object_permissions = False
    supports_anonymous_user = True

    def get_user(self, user_id):
        user_model = get_user_model()

        try:
            return user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return None

    def authenticate(self, **kwargs):
        try:
            credentials = kwargs.get('credentials')
            if not credentials:
                return None

            provider = credentials['provider']
            id_token = provider.verify_id_token(credentials['id_token'])

            oidc_user = OpenIDUser.get_or_create(
                id_token,
                credentials['access_token'],
                credentials.get('refresh_token', ''),
                provider)

            return oidc_user.user
        except Exception as e:
            log.error('Unexpected error on authentication: %s' % e)
            raise
