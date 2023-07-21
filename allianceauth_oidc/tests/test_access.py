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


"""    def test_with_perms_wrong_state_oauth_u1(self):
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type':'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'email',
                'state': "asdfghhjkl"
            }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        self.assertIn(f"{self.oauth_app.name} Access Denied", response.content.decode("utf-8"))
"""
