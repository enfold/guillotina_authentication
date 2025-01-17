import logging
import math
import time
from lru import LRU

from guillotina_authentication.user import OAuthUser
from guillotina_authentication import utils
from guillotina.contrib import cache
from guillotina.exceptions import ContainerNotFound
from guillotina.utils import get_current_container

logger = logging.getLogger(__name__)

USER_CACHE_DURATION = 60 * 1
NON_IAT_VERIFY = {
    'verify_iat': False,
}

LOCAL_CACHE = LRU(500)


class OAuthClientIdentifier:

    def get_user_cache_key(self, login):
        return '{}-{}'.format(
            login,
            math.ceil(math.ceil(time.time()) / USER_CACHE_DURATION)
        )

    async def get_user(self, token):
        if token.get('type') not in ('bearer', 'wstoken', 'cookie'):
            return
        if '.' not in token.get('token', ''):
            # quick way to check if actually might be jwt
            return

        validated_jwt = token['decoded']

        # XXX: If this JWT was not generated by guillotina, add info
        if 'client' not in validated_jwt:
            validated_jwt['client'] = 'keycloak'

        if 'client_args' not in validated_jwt:
            client_args = dict(
                access_token=token['token'])
        else:
            client_args = validated_jwt['client_args']

        try:
            container = get_current_container()
        except ContainerNotFound:
            container = None

        user = None
        cache_key = self.get_user_cache_key(token['token'])
        try:
            user = LOCAL_CACHE[cache_key]
        except KeyError:
            pass

        if user and container:
            await user.apply_scope(validated_jwt, container.id)

        if user:
            return user

        else:
            try:
                client = utils.get_client(
                    validated_jwt['client'], **client_args)
                user, user_data = await client.user_info()
            except Exception:
                logger.warning(
                    f'Error getting user data for {token}', exc_info=True)
                return

            # XXX: If this JWT was not generated by guillotina, add info
            if 'allowed_scopes' not in validated_jwt:
                validated_jwt['allowed_scopes'] = user_data.get('allowed_scopes')
                validated_jwt['scope'] = user_data.get('scope', '').split(' ')

            user = OAuthUser(user_id=user.id, properties=user_data)

            if container is not None:
                await user.apply_scope(validated_jwt, container.id)
            LOCAL_CACHE[cache_key] = user
            return user
