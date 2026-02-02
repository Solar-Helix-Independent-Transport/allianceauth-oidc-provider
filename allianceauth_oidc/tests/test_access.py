from allianceauth.authentication.models import State
from django.conf import settings
from django.shortcuts import resolve_url

from . import OIDCTestCase


class TestCorptoolsCharAccessPerms(OIDCTestCase):

    def test_anonymous_post_is_redirected_to_login_with_next(self):
        """
        Anonymous POST to /o/authorize/ must redirect to the login page
        with a "next" param.
        Only the path is preserved for POST (body params are not).
        """
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "abc",
            "allow": True,
        }

        resp = self.client.post("/o/authorize/", data=data)
        _, path, qs = self.parse_redirect(resp, (302,))

        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)

        actual_next = qs["next"][0]
        self.assertEqual("/o/authorize/", actual_next)

    def test_anonymous_is_redirected_to_login_with_next(self):
        """
        Anonymous GET to /o/authorize/ must redirect to the login page
        with a "next" param.
        """
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "abc",
        }

        resp = self.client.get("/o/authorize/", data=params)
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)
        expected_next = resp.wsgi_request.get_full_path()
        actual_next = qs["next"][0]
        self.assertEqual(expected_next, actual_next)

    def test_no_perms_oauth_u1(self):
        response = self.authorize_get(self.user1)
        self.assertDeniedGlobal(response, self.user1)

    def test_post_no_perms_oauth_u1(self):
        """
        Regression test: POST /o/authorize/ must NOT bypass access checks.
        """
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "post-bypass-test",
            "allow": True,
        }
        response = self.authorize_post(self.user1, data=data)
        self.assertDeniedGlobal(response, self.user1)

    def test_with_perms_oauth_u1_all_scopes(self):
        """
        Check that all requested scopes are shown when user has access
        """
        self.grant_oidc_access(self.user1)
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(
            response, self.oauth_app, ["openid", "email", "profile"]
        )

    def test_with_perms_oauth_u1_email_only(self):
        """
        Check that only requested scopes are shown when user has access
        """
        self.grant_oidc_access(self.user1)
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(response, self.oauth_app, ["email"])

    def test_with_perms_and_state_oauth_u1(self):
        """
        Check that scopes are shown when user has access and correct state
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(
            response, self.oauth_app, ["email", "openid", "profile"]
        )

    def test_full_chain_u1_with_perms_and_state(self):
        """
        Test full OAuth2 authorization code flow for user1
        with proper permissions and state
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_wrong_state(self):
        """
        Test full OAuth2 authorization code flow for user1
        """
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_state"
        scopes = "openid profile email"
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)

    def test_full_chain_u1_with_perms_and_wrong_state_and_group(self):
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_group(self):
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_wrong_group(self):
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_group"
        scopes = "openid profile email"
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)

    def test_full_chain_u1_with_perms_and_wrong_group_and_state(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_group_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_get_u1_without_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_get_u1_without_perms_and_group_and_state"
        scopes = "openid profile email"
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)

    def test_full_chain_u1_with_su(self):
        # wrong state to test bypass for SU
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.is_superuser = True
        self.user1.save()
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )
