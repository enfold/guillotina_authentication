import yarl
import logging
from datetime import datetime
from datetime import timedelta
from aiohttp import web
from guillotina import api, app_settings, configure
from guillotina.component import get_utility
from guillotina.api.service import Service
from guillotina.auth import authenticate_user
from guillotina.component import get_multi_adapter
from guillotina.event import notify
from guillotina.events import UserLogin
from guillotina.interfaces import IApplication, IContainer, ICacheUtility, IResourceSerializeToJsonSummary
from guillotina.response import HTTPBadRequest, HTTPFound, HTTPNotFound
from guillotina.utils import get_url
from guillotina.utils import get_authenticated_user
from guillotina_authentication import exceptions, utils, CACHE_PREFIX
from guillotina_authentication.user import OAuthUser

http_exception_mappings = {
    exceptions.ProviderNotSupportedException: (
        HTTPNotFound, '{provider} is not supported'),
    exceptions.ProviderNotConfiguredException: (
        HTTPNotFound, '{provider} is not configured'),
    exceptions.ProviderMisConfiguredException: (
        HTTPNotFound, '{provider} is misconfigured'),
}

logger = logging.getLogger(__name__)


@configure.service(context=IApplication, method='GET',
                   name='@authentication-providers', allow_access=True)
@configure.service(context=IContainer, method='GET',
                   name='@authentication-providers', allow_access=True)
async def auth_providers(context, request):
    return list(set(
        app_settings['auth_providers']) & set(utils.config_mappings.keys()))


@configure.service(context=IApplication, method='GET',
                   name='@authenticate/{provider}', allow_access=True,
                   parameters=[{
                        'in': 'query',
                        'name': 'scope',
                        'description': 'scape separated list'
                   }])
@configure.service(context=IContainer, method='GET',
                   name='@authenticate/{provider}', allow_access=True,
                   parameters=[{
                        'in': 'query',
                        'name': 'scope',
                        'description': 'scape separated list'
                   }])
async def auth(context, request):
    provider = request.matchdict['provider']
    try:
        client = utils.get_client(provider)
    except exceptions.AuthenticationException as exc:
        if type(exc) in http_exception_mappings:
            ExcType, reason = http_exception_mappings[type(exc)]
            raise ExcType(content={
                'reason': reason.format(provider=provider)
            })
    if 'callback' not in request.query:
        callback_url = f'{get_url(request, "/")}@callback/{provider}'
    else:
        callback_url = request.query.get('callback')

    return HTTPFound(await utils.get_authentication_url(
        client, callback=callback_url,
        scope=request.query.get('scope') or ''))


@configure.service(context=IApplication, method='GET',
                   name='@authorize/{provider}', allow_access=True,
                   parameters=[{
                        'in': 'query',
                        'name': 'scope',
                        'description': 'scape separated list'
                   }])
@configure.service(context=IContainer, method='GET',
                   name='@authorize/{provider}', allow_access=True,
                   parameters=[{
                        'in': 'query',
                        'name': 'scope',
                        'description': 'scape separated list'
                   }])
async def authorize(context, request):
    provider = request.matchdict['provider']
    try:
        client = utils.get_client(provider)
    except exceptions.AuthenticationException as exc:
        if type(exc) in http_exception_mappings:
            ExcType, reason = http_exception_mappings[type(exc)]
            raise ExcType(content={
                'reason': reason.format(provider=provider)
            })

    if 'callback' not in request.query:
        callback_url = f'{get_url(request, "/")}/@callback/{provider}'
    else:
        callback_url = request.query.get('callback')
    return HTTPFound(await utils.get_authorization_url(
        client, callback=callback_url,
        scope=request.query.get('scope') or ''))


@configure.service(context=IApplication, method='GET',
                   name='@callback/{provider}', allow_access=True)
@configure.service(context=IContainer, method='GET',
                   name='@callback/{provider}', allow_access=True)
async def auth_callback(context, request):
    provider = request.matchdict['provider']

    if provider in utils.oauth1_providers:
        oauth_verifier = request.url.query.get('oauth_verifier')
        oauth_token = request.url.query.get('oauth_token')
        client = utils.get_client(provider, oauth_token=oauth_token)
        cache_utility = get_utility(ICacheUtility)
        request_token = await cache_utility.get(CACHE_PREFIX + oauth_token)
        if request_token is None:
            raise web.HTTPBadRequest(
                reason='Failed to obtain proper request token.')
        oauth_token, oauth_token_secret, otoken_data = await client.get_access_token(  # noqa
            oauth_verifier, oauth_token)

        client_args = dict(
            oauth_token=oauth_token,
            oauth_token_secret=oauth_token_secret)
    else:
        client = utils.get_client(provider)
        if 'error' in request.query:
            raise HTTPBadRequest(content=dict(request.query))

        if 'code' not in request.query:
            raise HTTPBadRequest(content=dict(request.query))

        code = request.query.get('code')

        callback_url = f'{get_url(request, "/")}@callback/{provider}'

        forwarded_proto = request.headers.get('X-Forwarded-Proto', None)
        if forwarded_proto and forwarded_proto != request.scheme:
            callback_url = callback_url.replace(
                request.scheme + '://', forwarded_proto + '://')

        otoken, otoken_data = await client.get_access_token(
            code, redirect_uri=callback_url)

        client_args = dict(
            access_token=otoken,
            refresh_token=otoken_data['refresh_token'])

    if 'expires_in' in otoken_data:
        timeout = otoken_data['expires_in']
    else:
        timeout = 60 * 60 * 1

    client = utils.get_client(provider, **client_args)
    user, user_data = await client.user_info()
    groups = list()
    for groupname in user_data.get('groups', list()):
        name = groupname
        if groupname.startswith('/'):
            name = name[1:]
        groups.append(name)

    jwt_token, data = authenticate_user(user.id, {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'username': user.username,
        'client': provider,
        'client_args': client_args,
        'groups': groups,
        'allowed_scopes': user_data.get('allowed_scopes'),
        'scope': request.query.get('scope', '').split(' '),
        'identifier': 'oauth'
    }, timeout=timeout)

    await notify(UserLogin(user, jwt_token))
    result = {
        'exp': data['exp'],
        'token': jwt_token
    }

    if app_settings.get('auth_callback_url'):
        url = yarl.URL(app_settings['auth_callback_url'])
        response = HTTPFound(str(url))
    else:
        response = HTTPFound(get_url(request, "/"))
    #breakpoint()
    expires = datetime.utcnow() + timedelta(seconds=timeout)
    expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
    response.headers['Set-Cookie'] = f"auth_token={jwt_token}; Path=/; Expires={expires}"
    #return result
    return response


@configure.service(
    context=IApplication, method='GET', allow_access=True,
    permission='guillotina.AccessContent', name='@user',
    summary='Get information on the currently logged in user')
async def user_info(context, request):
    return await api.user.get_user_info(context, request)



@configure.service(
    context=IContainer,
    method="POST",
    permission="guillotina.RefreshToken",
    name="@login-renew",
    summary="Refresh to a new token",
    allow_access=True,
)
@configure.service(
    context=IApplication,
    method="POST",
    permission="guillotina.RefreshToken",
    name="@login-renew",
    summary="Refresh to a new token",
    allow_access=True,
)
class OauthRefresh(api.login.Refresh):
    async def __call__(self):
        user = get_authenticated_user()
        if isinstance(user, OAuthUser):
            result = await user.refresh()
        else:
            result = await super(OauthRefresh, self).__call__()
        return result


@configure.service(
    context=IContainer,
    name="@users/{user}",
    method="GET",
    permission="guillotina.AccessContent",
    responses={
        "200": {
            "description": "User data",
            # TODO: add response content schema here
        },
        "404": {"description": "User not found"},
    },
    summary="Get user data",
    allow_access=True,
)
class GetUser(Service):
    async def get_user(self) -> OAuthUser:
        user_id: str = self.request.matchdict["user"]
        user = get_authenticated_user()
        if (user and user.id != user_id) or user is None:
            raise HTTPNotFound(content={"reason": f"User {user_id} not found"})
        return user

    async def __call__(self) -> dict:
        user: OAuthUser = await self.get_user()
        user_data = {
            "username": user.username,
            "fullname": f"{user.first_name} {user.last_name}",
            "email": user.email,
            "id": user.id,
            "roles": user.roles,
            "user_groups": user.groups,
        }

        return user_data
