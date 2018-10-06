import os
from datetime import datetime, timedelta
from hashlib import sha1
from urllib.parse import urlencode

import aioauth_client
import jwt
import yarl
from aiohttp import web
from guillotina import app_settings, configure
from guillotina.event import notify
from guillotina.events import UserLogin
from guillotina.response import HTTPBadRequest, HTTPFound, HTTPNotFound
from guillotina_authentication import cache, exceptions

aioauth_client.TwitterClient.authentication_url = 'https://api.twitter.com/oauth/authenticate'  # noqa


class HydraClient(aioauth_client.OAuth2Client):

    @property
    def user_info_url(self):
        return os.path.join(self.base_url, 'userinfo')

    @staticmethod
    def user_parse(data):
        return {
            'id': data['sub'],
            'displayName': 'Foobar'
        }


config_mappings = {
    'twitter': aioauth_client.TwitterClient,
    'facebook': aioauth_client.FacebookClient,
    'github': aioauth_client.GithubClient,
    'google': aioauth_client.GoogleClient,
    'hydra': HydraClient
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
    if provider not in app_settings['auth_providers']:
        raise exceptions.ProviderNotConfiguredException(provider)
    provider_config = app_settings['auth_providers'][provider]
    if 'configuration' not in provider_config:
        raise exceptions.ProviderMisConfiguredException(provider)
    configuration = provider_config['configuration']
    if provider not in config_mappings:
        # in this case, make sure we have all necessary config to build
        if ('authorize_url' not in configuration or
                'access_token_url' not in configuration):
            raise exceptions.ProviderNotSupportedException(provider)
    kwargs.update(configuration)
    if provider not in config_mappings:
        ProviderClass = aioauth_client.OAuth2Client
    else:
        ProviderClass = config_mappings[provider]
    client = ProviderClass(**kwargs)
    client.provider = provider
    client.send_state = provider_config.get('state') or False
    return client


async def get_authorization_url(client, *args, callback=None, **kwargs):
    config = app_settings['auth_providers'][client.provider]
    if 'scope' in config:
        kwargs['scope'] = config['scope']

    args = list(args)
    url = kwargs.pop('url', client.authorize_url)
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
        if client.send_state:
            params['state'] = sha1(str(
                aioauth_client.RANDOM()).encode('ascii')).hexdigest()
            await cache.put(params['state'], 'nonce')
        return url + '?' + urlencode(params)


async def get_authentication_url(client, *args, callback=None, **kwargs):
    if not hasattr(client, 'authentication_url'):
        return await get_authorization_url(
            client, *args, callback=callback, **kwargs)
    kwargs['url'] = client.authentication_url
    return await get_authorization_url(
        client, *args, callback=callback, **kwargs)


@configure.service(method='GET', name='@authentication-providers',
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
    else:
        client = get_client(provider)
        if 'error' in request.url.query:
            raise HTTPBadRequest(content=dict(request.url.query))
        code = request.url.query['code']
        otoken, _ = await client.get_access_token(
            code,
            redirect_uri=str(request.url.with_path('@callback/' + provider)))

        client = get_client(
            provider,
            access_token=otoken,
        )

    user, user_data = await client.user_info()

    data = {
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 1),
        'id': f"{provider}:{user.id}",
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'username': user.username,
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
