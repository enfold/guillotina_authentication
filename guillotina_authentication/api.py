from guillotina import configure
from guillotina.event import notify
from guillotina.events import UserLogin
from aiohttp import web
from urllib.parse import urlencode
from guillotina import app_settings
from guillotina.response import HTTPNotFound, HTTPFound
import aioauth_client
from guillotina_authentication import exceptions
from guillotina_authentication import cache
from datetime import datetime, timedelta
import jwt
import yarl

aioauth_client.TwitterClient.authentication_url = 'https://api.twitter.com/oauth/authenticate'  # noqa

config_mappings = {
    'twitter': aioauth_client.TwitterClient,
    'facebook': aioauth_client.FacebookClient,
    'github': aioauth_client.GithubClient,
    'google': aioauth_client.GoogleClient
}

oauth1_providers = ('twitter', )


http_exception_mappings = {
    exceptions.ProviderNotSupportedException: (
        HTTPNotFound, '{provider} is not supported'),
    exceptions.ProviderNotConfiguredException: (
        HTTPNotFound, '{provider} is not configured'),
    exceptions.ProviderMisConfiguredException: (
        HTTPNotFound, '{provider} is misconfigured'),
}


def get_client(provider, **kwargs):
    if provider not in config_mappings:
        raise exceptions.ProviderNotSupportedException(provider)
    if provider not in app_settings['auth_providers']:
        raise exceptions.ProviderNotConfiguredException(provider)
    config = app_settings['auth_providers'][provider]
    if 'configuration' not in config:
        raise exceptions.ProviderMisConfiguredException(provider)
    kwargs.update(config['configuration'])
    client = config_mappings[provider](**kwargs)
    client.provider = provider
    return client


async def get_authorization_url(client, *args, **kwargs):
    config = app_settings['auth_providers'][client.provider]
    if 'scope' in config:
        kwargs['scope'] = config['scope']

    args = list(args)
    if client.provider in oauth1_providers:
        request_token, request_token_secret, _ = await client.get_request_token(**kwargs)  # noqa
        args.append(request_token)
        kwargs = {}
    return HTTPFound(client.get_authorize_url(*args, **kwargs))


async def get_authentication_url(client, *args, callback=None, **kwargs):
    config = app_settings['auth_providers'][client.provider]
    if 'scope' in config:
        kwargs['scope'] = config['scope']

    args = list(args)
    url = getattr(
        client, 'authentication_url',
        client.authorize_url)
    if client.provider in oauth1_providers:
        request_token, request_token_secret, _ = await client.get_request_token(  # noqa
            oauth_callback=callback
        )
        args.append(request_token)
        params = {'oauth_token': request_token or client.oauth_token}
        await cache.put(request_token, request_token_secret)
        return url + '?' + urlencode(params)
    else:
        params = dict(client.params, **kwargs)
        params.update({
            'client_id': client.client_id, 'response_type': 'code',
            'redirect_uri': callback
        })
        return url + '?' + urlencode(params)


@configure.service(method='GET', name='@auth-providers',
                   allow_access=True)
async def auth_providers(context, request):
    return list(set(app_settings['auth_providers']) & set(config_mappings.keys()))


@configure.service(method='GET', name='@authenticate/{provider}',
                   allow_access=True)
async def auth(context, request):
    provider = request.matchdict['provider']
    try:
        client = get_client(provider)
    except exceptions.AuthenticationException as exc:
        if type(exc) in http_exception_mappings:
            ExcType, reason = http_exception_mappings[type(exc)]
            raise ExcType(content={
                'reason': reason.format(provider=provider)
            })
    callback_url = str(request.url.with_path('@callback/' + provider))
    return HTTPFound(await get_authentication_url(
        client, callback=callback_url))


@configure.service(method='GET', name='@authorize/{provider}',
                   allow_access=True)
async def authorize(context, request):
    provider = request.matchdict['provider']
    try:
        client = get_client(provider)
    except exceptions.AuthenticationException as exc:
        if type(exc) in http_exception_mappings:
            ExcType, reason = http_exception_mappings[type(exc)]
            raise ExcType(content={
                'reason': reason.format(provider=provider)
            })
    callback_url = str(request.url.with_path('@callback/' + provider))
    return HTTPFound(await get_authorization_url(
        client, callback=callback_url))


@configure.service(method='GET', name='@callback/{provider}',
                   allow_access=True)
async def auth_callback(context, request):
    provider = request.matchdict['provider']

    if provider in oauth1_providers:
        oauth_verifier = request.url.query.get('oauth_verifier')
        oauth_token = request.url.query.get('oauth_token')
        client = get_client(provider, oauth_token=oauth_token)
        request_token = await cache.get(oauth_token)
        if request_token is None:
            raise web.HTTPBadRequest(
                reason='Failed to obtain proper request token.')
        oauth_token, oauth_token_secret, _ = await client.get_access_token(
            oauth_verifier, oauth_token)

        # store to retrieve again later
        await cache.put(oauth_token, oauth_token_secret,
                        expires=60 * 60 * 24 * 365)

        client = get_client(
            provider,
            oauth_token=oauth_token,
            oauth_token_secret=oauth_token_secret)
        user, user_data = await client.user_info()
    else:
        client = get_client(provider)
        code = request.url.query['code']
        otoken, _ = await client.get_access_token(
            code,
            redirect_uri=str(request.url.with_path('@callback/' + provider)))

        client = get_client(
            provider,
            access_token=otoken,
        )
        user, user_data = await client.user_info()

    email = user_data.get('email')
    if 'emails' in user_data:
        for em in user_data['emails']:
            if isinstance(em, dict):
                if 'value' in em:
                    email = em['value']
                    break
            else:
                email = em
    username = user_data.get('nickname', user_data.get('screen_name'))
    data = {
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 1),
        'id': f"{provider}:{user_data['id']}",
        'name': user_data.get('displayName', user_data.get('name')),
        'email': email,
        'username': username,
    }
    jwt_token = jwt.encode(data, app_settings['jwt']['secret']).decode('utf-8')

    await notify(UserLogin(user, jwt_token))

    result = {
        'exp': data['exp'],
        'token': jwt_token
    }
    if app_settings.get('auth_callback_url'):
        url = yarl.URL(
            app_settings['auth_callback_url']).with_query(result)
        return HTTPFound(str(url))
    return result
