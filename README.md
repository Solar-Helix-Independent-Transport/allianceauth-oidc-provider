# allianceauth_oidc

## Allianceauth OIDC Provider

### Beta Testing ONLY!

## Features

- OIDC / OAuth2
  - Scopes Available
    - openid
    - email
    - profile
      - Includes `groups` claim with all a members groups and state as a list of strings
- Application level permissions
  - global access
  - State access
  - group access

## Setup/Install:

1. `pip install allianceauth-oidc-provider`
1. add to INSTALLED_APPS

   ```
       'allianceauth_oidc',
       'oauth2_provider',
   ```

1. Extra Settings Required

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

   Please see [this](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key) for more info on creating and managing a private key

1. Add the endpoints to your `urls.py`

   ```
       path('o/', include('allianceauth_oidc.urls', namespace='oauth2_provider')),
   ```

1. run migrations
1. restart auth

## Application setup

### The Big 4

- Authorization: `https://your.url/o/authorize/`
- Token: `https://your.url/o/token/`
- Profile: `https://your.url/o/userinfo/`
- Issuer `http://your.url/o` **yes that is **http** not http**

### Claims

- `openid profile email`

### Claim key mapping

- `name` Eve Main Character Name ( Profile Grant? )
- `email` Registered email on auth ( Email Grant )
- `groups` List of all groups with the members state thrown in too ( Profile Grant )
- `sub` PK of user model

### WikiJS

Manually create and groups you care for your users to have in the wiki and the service will map them for you. This greatly cuts down on group spam.
in auth create `Administrators` to give access to the full wiki admin site.

#### Administration > Authentication > Generic OpenID Connect / OAuth2

- Skip User Profile `off`
- Email claim `email`
- Display Name Claim `name`
- Map Groups `on`
- Groups Claim `groups`
- Allow Self Registration `on`

### Grafana

Tested only with access no group mapping as yet

**TODO** get the group links working

#### /etc/grafana/grafana.ini

```ini
[auth.generic_oauth]
enabled = true
name = Your Site Name
allow_sign_up = true
client_id = ******
client_secret = *****
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://your.url/o/authorize/
token_url = https://your.url/o/token/
api_url = https://your.url/o/userinfo/
```
