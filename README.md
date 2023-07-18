# allianceauth_oidc

### allianceauth_oidc

WIP, MVP, Alpha Level Testing ONLY

Setup/Install:

add to INSTALLED_APPS

```
    'allianceauth_oidc',
    'oauth2_provider',
```

Settings Required

```python
OAUTH2_PROVIDER_APPLICATION_MODEL='allianceauth_oidc.AllianceAuthApplication'
OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    # https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key
    "OIDC_RSA_PRIVATE_KEY": os.environ.get('OIDC_RSA_PRIVATE_KEY'), ## Load your private key into an env variable
    "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
    "SCOPES": {
        "openid": "User Profile",
        "email": "User email",
        "profile": "Affiliations and Groups"
        },
    "PKCE_REQUIRED": False,
    "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
    'ACCESS_TOKEN_EXPIRE_SECONDS': 60,
    'REFRESH_TOKEN_EXPIRE_SECONDS': 24*60*60,
    'ROTATE_REFRESH_TOKEN': True,
}
```

URLs file edits

add

```
    path('o/', include('allianceauth_oidc.urls', namespace='oauth2_provider')),
```

run migrations
restart auth
