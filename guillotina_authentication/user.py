from guillotina.auth.users import GuillotinaUser
from guillotina_authentication import utils
from guillotina.auth import authenticate_user
from guillotina.contrib.dbusers.content.groups import Group
from guillotina.interfaces.content import IDatabase
from guillotina.utils import get_current_container
from guillotina.utils import navigate_to
import logging
import typing


logger = logging.getLogger("guillotina_authentication.user")


class OAuthUser(GuillotinaUser):

    def __init__(self, user_id, properties):
        super(OAuthUser, self).__init__(user_id, properties)
        self._validated_jwt = None

    async def apply_scope(self, validated_jwt, container_id):
        self._validated_jwt = validated_jwt
        allowed_scopes = validated_jwt.get('allowed_scopes') or []

        if 'groups' in validated_jwt:
            self._groups = validated_jwt.get('groups') or []

        for scope in validated_jwt.get('scope') or []:
            if scope not in allowed_scopes:
                continue
            split = scope.split(':')
            if len(split) not in (2, 3):
                continue
            if len(split) == 3:
                if container_id is None:
                    # on root, do not apply this guy...
                    continue
                if container_id != split[0]:
                    continue
            if split[-2] == 'role':
                self._roles[split[-1]] = 1
            if split[-2] == 'permission':
                self._permissions[split[-1]] = 1

        # Get roles and permissions from the group membership
        # XXX: This is a hack, since creating a group
        # actually creates a "Group" type, which is different from
        # the "GuillotinaGroup" as found by guillotina/api/user.py get_user_info

        container = get_current_container()
        if container:
            # We want to go to the root object
            site = container
            while not IDatabase.providedBy(container):
                site = container
                container = container.__parent__

            for groupname in self._groups:
                try:
                    group: typing.Optional[Group] = await navigate_to(site, "groups/{}".format(groupname))
                except KeyError:
                    group = None
                except Exception:
                    logger.error("Error getting group", exc_info=True)
                    group = None
                if group:
                    self._roles.update(group.roles)
                    self._permissions.update(group.permissions)


    async def refresh(self, scopes):
        client = utils.get_client(
            self._validated_jwt['client'],
            **self._validated_jwt['client_args'])

        refresh_token = self._validated_jwt['client_args']['refresh_token']
        otoken, otoken_data = await client.get_access_token(
            refresh_token, grant_type='refresh_token')

        client_args = dict(
            access_token=otoken,
            refresh_token=refresh_token)

        if 'expires_in' in otoken_data:
            timeout = otoken_data['expires_in']
        else:
            timeout = 60 * 60 * 1

        user, user_data = await client.user_info()

        jwt_token, data = authenticate_user(user.id, {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'username': user.username,
            'client': self._validated_jwt['client'],
            'client_args': client_args,
            'allowed_scopes': user_data.get('allowed_scopes'),
            'scope': scopes,
            'identifier': 'oauth'
        }, timeout=timeout)

        result = {
            'exp': data['exp'],
            'token': jwt_token
        }
        return result
