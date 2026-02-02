# allianceauth_oidc

## Allianceauth OIDC Provider

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

## Example

![Imgur](https://i.imgur.com/gcrFcRL.png)

## Setup/Install

1. `pip install allianceauth-oidc-provider`
1. add to `INSTALLED_APPS` in your `local.py`

   ```python
   INSTALLED_APPS += [
       # your other apps #
       'allianceauth_oidc',
       'oauth2_provider',
       # your other apps #
   ]
   ```

1. Extra Settings Required

   ```python

   # at the top of the file
   from pathlib import Path

   # Add these to the file further down
   if 'allianceauth_oidc' in INSTALLED_APPS and 'oauth2_provider' in INSTALLED_APPS:
       OAUTH2_PROVIDER_APPLICATION_MODEL='allianceauth_oidc.AllianceAuthApplication'
       OAUTH2_PROVIDER = {
           # https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key
           "OIDC_ENABLED": True,
           # Load your private key
           "OIDC_RSA_PRIVATE_KEY": Path("/path/to/key/file").read_text(),
           "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
           "SCOPES": {
               "openid": "User Profile",
               "email": "Registered email",
               "profile": "Main Character affiliation and Auth groups"
           },
           "PKCE_REQUIRED": False,
           "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
           'ACCESS_TOKEN_EXPIRE_SECONDS': 60,
           'REFRESH_TOKEN_EXPIRE_SECONDS': 24*60*60,
           'ROTATE_REFRESH_TOKEN': True,
       }
   ```

   Please see [this](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key)
   for more info on creating and managing a private key

1. Add the endpoints to your `urls.py`

   ```python
   from .settings.local import INSTALLED_APPS

   # ...
   # Here your other imports and urlpatterns
   # ...

   if "allianceauth_oidc" in INSTALLED_APPS and "oauth2_provider" in INSTALLED_APPS:
       urlpatterns.append(
           path(
               "o/",
               include("allianceauth_oidc.urls", namespace="oauth2_provider"),
           )
       )
   ```

1. run migrations
1. restart auth

## Optional settings (recommended)

### Masking secrets in debug logs

By default, the provider never logs raw token values or secrets. When an application has _Debug Mode_ enabled,
it can log additional debug metadata, but secrets remain redacted unless you explicitly allow masked output.

Add to your settings (optional):

```python
# When False (default): secrets are logged as "<redacted>"
# When True: secrets are logged as masked fragments (head…tail)
ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS = False

# How many characters of a secret to show in logs when masking is enabled
ALLIANCEAUTH_OIDC_LOG_MASK_HEAD = 2
ALLIANCEAUTH_OIDC_LOG_MASK_TAIL = 2
```

Security note: enable masked logging only if your log storage is properly restricted.

### Periodic cleanup of expired tokens (Celery Beat)

To prevent the database from growing indefinitely, schedule the cleanup task:

```python
from celery.schedules import crontab

CELERYBEAT_SCHEDULE["allianceauth_oidc_clear_expired_tokens"] = {
    "task": "allianceauth_oidc.clear_expired_tokens",
    "schedule": crontab(minute=0, hour="*/2"),  # every 2 hours
    "apply_offset": True,
}
```

## Application setup

### The Big 4

- Authorization: `https://your.url/o/authorize/`
- Token: `https://your.url/o/token/`
- Profile: `https://your.url/o/userinfo/`
- Issuer `https://your.url/o/`

### Claims

- `openid profile email`

### Claim key mapping

- `name` Eve Main Character Name ( Profile Grant )
- `email` Registered email on auth ( Email Grant )
- `groups` List of all groups with the members state thrown in too ( Profile Grant )
- `sub` PK of user model
- `picture` URL to the main character avatar ( Profile Grant )
- `locale` User preferred language ( Profile Grant )

### Create an application

Before configuring the external application you want to go on your auth admin pannel at `/admin/allianceauth_oidc` and create a new alliance auth application.

- `User` can be set to 1, this is a parameter for the upstream library not used in this application
- `client type` should be confidential
- `authorization grant type` should be `Authorization code`
- `Client secret` needs to be saved somewhere **before** hitting save if you leave the hashing on (it won't be displayed again)
- `Algorithm`: `RSA with SHA-2 256`

Then you can set which states or group can access this application. \
_Note that they will also need the `allianceauth_oidc.access_oidc` role to access any application._

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

Group>Team mapping requires Grafana cloud or Enterprise and is outside of the scope of this doc.

#### /etc/grafana/grafana.ini

```ini
[server]
root_url = <URL of your grafana server>

[auth.generic_oauth]
enabled = true
name = <Your Auth Name>
allow_sign_up = true
client_id = <client id from the application>
client_secret = <client secret from the application (unhashed)>
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://<your.auth.url>/o/authorize/
token_url = https://<your.auth.url>/o/token/
api_url = https://<your.auth.url>/o/userinfo/
```

### Debugging an application

1. Enable _Debug Mode_ for the specific application in the auth admin site.
1. then in your `gunicorn.log` look for long lines similar to this after you attempt to log in,

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views:78] OIDC DEBUG token issued app_id='...' client_id='...' user_id='...' meta={'grant_type': 'authorization_code', 'scope': 'openid email profile', 'client_id': '...', 'redirect_uri': '...', 'code': '<redacted>', 'refresh_token_req': None, 'client_secret': None, 'assertion': None, 'token_type': 'Bearer', 'expires_in': 111, 'scope_resp': 'openid email profile', 'access_token': '<redacted>', 'refresh_token': '<redacted>', 'id_token': '<redacted>'}
```

1. take the `id_token` field and paste it into https://jwt.io/ to debug the data being sent to the application. it should be fairly self explanitory expect for these 2 fields.

- `iss` is the issuer that must match exactly in the applications own settings.
- `sub` is your user id if you need to debug why user is being sent.

If you want to check the token signature on jwt.io and lost your public key your can use:

```sh
ssh-keygen -y -e -m pem -f /path/to/key/file
```

This will output the public key in the PEM format for jwt.io to check the signature.

> [!NOTE]
> If you are using a custom theme (or have overridden the public login template),
> please double-check your login page template at:
> `authentication/templates/public/login.html`
> Make sure the SSO login link URL-encodes the next parameter.
> Otherwise, query parameters can be truncated and OAuth/OIDC
> flows may fail (e.g. missing client_id after redirect).
>
> ```html
> <a
>   href="{% url 'auth_sso_login' %}{% if request.GET.next %}?next={{ request.GET.next | urlencode }}{% endif %}"
> ></a>
> ```
