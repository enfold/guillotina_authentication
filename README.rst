guillotina_authentication Docs
==============================

This guillotina app provides authentication through different providers:

- [x] twitter
- [x] google
- [x] github
- [ ] facebook
- [ ] ORY hydra based?


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

    # frontend url to handle storing auth
    auth_callback_url: http://localhost:8080/foobar



Endpoints:

 - GET /@auth-providers
 - GET /@authorize/{provider}
 - GET /@callback/{provider}
