import json
from urllib.parse import parse_qs

from allianceauth.authentication.models import State

from django.contrib.sessions.middleware import SessionMiddleware
from django.http import (
    Http404, HttpResponse, HttpResponseBadRequest, HttpResponseRedirect,
)

from ..views import AuthorizationView, TokenView
from . import OIDCTestCase


class TestCorptoolsCharAccessPerms(OIDCTestCase):

    def test_no_perms_oauth_u1(self):
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/')

        self.assertIn("External OAuth Denied",
                      response.content.decode("utf-8"))

    def test_with_perms_oauth_u1_all_scopes(self):
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'openid profile email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertIn(f"profile", response.content.decode("utf-8"))

    def test_with_perms_oauth_u1_email_only(self):
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertNotIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertNotIn(f"profile", response.content.decode("utf-8"))

    def test_with_perms_and_state_oauth_u1(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'openid profile email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertIn(f"profile", response.content.decode("utf-8"))

    def test_full_chain_u1_with_perms_and_state(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])

        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEquals(scopes, get_params['scope'])
        self.assertEquals(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])
        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEquals(scopes, get_params['scope'])
        self.assertEquals(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_group(self):
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])
        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEquals(scopes, get_params['scope'])
        self.assertEquals(60, get_params['expires_in'])

    def test_get_u1_without_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(f"{self.oauth_app} Access Denied",
                      response.content.decode("utf-8"))
        self.assertEquals(200, response.status_code)

    def test_full_chain_u1_with_su(self):
        # wrong state to test bypass for SU
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.is_superuser = True
        self.user1.save()
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])

        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEquals(scopes, get_params['scope'])
        self.assertEquals(60, get_params['expires_in'])
