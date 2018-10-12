guillotina_authentication Docs
==============================

This guillotina app provides authentication through different providers:

- [x] twitter
- [x] google
- [x] github
- [x] ORY hydra based?
- [ ] facebook (untested)


Example configuration::

    auth_providers:
      twitter:
        configuration:
          consumer_key: foobar
          consumer_secret: foobar
      google:
        configuration:
          client_id: foobar
          client_secret: foobar
        scope: openid email
      github:
        configuration:
          client_id: foobar
          client_secret: foobar
        scope: read:user
      hydra:
        configuration:
          client_id: auth-code-client
          client_secret: secret
          base_url: http://localhost:4444/
          authorize_url: http://localhost:4444/oauth2/auth
          access_token_url: http://localhost:4444/oauth2/token
        state: true
        scope: openid offline

    # frontend url to handle storing auth
    auth_callback_url: http://localhost:8080/foobar
    auth_user_identifiers
    - guillotina_authentication.identifier.OAuthClientIdentifier



Endpoints
---------

 - GET /@authentication-providers
 - GET /@authorize/{provider}
 - GET /@authenticate/{provider}
 - GET /@callback/{provider}


TODO
----

- be able to specify custom scopes to authenicate with
