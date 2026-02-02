import json
from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings
from . import OIDCTestCase


def _enable_rp_logout():
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.setdefault("OIDC_ENABLED", True)
    cfg["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
    return cfg


class TestTokenPolicy(OIDCTestCase):

    def _issue_code_user1_with_group_access(self) -> str:
        self.oauth_app.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "policy-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        return code

    def test_token_exchange_denied_if_group_removed_after_code_issued(self):
        """
        If the user stops matching policy (group/state) after code issuance,
        /o/token/ must fail with invalid_grant.
        """
        code = self._issue_code_user1_with_group_access()

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri="http://localhost/redir/",
            expected_status=400,
        )
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_group_removed(self):
        """
        Refresh token exchange must enforce policy and deny if access
        was removed.
        """
        code = self._issue_code_user1_with_group_access()

        token_resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        body = self.assertTokenResponse(
            token_resp,
            expected_scope="openid profile email",
            expected_expires_in=60,
        )
        refresh = body["refresh_token"]

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_userinfo_returns_expected_claims(self):
        """
        /o/userinfo/ returns additional claims:
        name, picture, groups (+ email if set).
        """
        self.grant_oidc_access(self.user1)
        self.user1.email = "user1@example.com"
        self.user1.save()
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "userinfo-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        token_resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        tokens = self.assertTokenResponse(token_resp)
        access_token = tokens["access_token"]

        resp = self.client.get(
            "/o/userinfo/", HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        self.assertEqual(200, resp.status_code)
        info = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(info, dict)

        self.assertEqual(self.char1.character_name, info.get("name"))
        self.assertIn(str(self.char1.character_id), info.get("picture", ""))

        self.assertIn("groups", info)
        self.assertIsInstance(info["groups"], list)
        self.assertIn(self.test_grp.name, info["groups"])

        self.assertEqual("user1@example.com", info.get("email"))

    def test_inactive_app_cannot_issue_code(self):
        """
        AllianceAuthApplication.active=False must make the app unusable.
        It must not issue a code redirect to redirect_uri.
        """
        self.grant_oidc_access(self.user1)

        self.oauth_app.active = False
        self.oauth_app.save()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "inactive-app",
            "allow": True,
        }
        resp = self.authorize_post(self.user1, data=data)

        if resp.status_code == 302:
            loc, _, qs = self.parse_redirect(resp, (302,))
            self.assertTrue(loc.startswith("http://localhost/redir/"))
            self.assertNotIn("code", qs)
            self.assertIn("error", qs)
            self.assertTrue(qs["error"][0])
        else:
            self.assertNotEqual(302, resp.status_code)

    def test_token_exchange_denied_if_redirect_uri_mismatch(self):
        """
        If redirect_uri used in /o/token/ doesn't match the one used
        in /o/authorize/, token exchange must fail (typically invalid_grant).
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "redir-mismatch",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/other/",
            expected_status=400,
        )

        body = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn(body.get("error"), {"invalid_grant", "invalid_request"})

    def test_debug_logging_does_not_leak_tokens_or_secrets(self):
        """
        When app.debug_mode=True, TokenView logs safe metadata.
        Ensure raw tokens/secrets are never present in logs.
        """
        self.grant_oidc_access(self.user1)

        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "log-leak-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="INFO"
        ) as cm:
            token_resp = self.exchange_code_for_token(
                code=code,
                redirect_uri="http://localhost/redir/",
                expected_status=200,
            )

        tokens = self.assertTokenResponse(token_resp)

        log_text = "\n".join(cm.output)

        self.assertIn("OIDC DEBUG token issued", log_text)

        self.assertNotIn(tokens["access_token"], log_text)
        self.assertNotIn(tokens["refresh_token"], log_text)
        self.assertNotIn(tokens["id_token"], log_text)

        self.assertNotIn(code, log_text)

        self.assertNotIn(self.oauth_secret, log_text)

    def test_refresh_token_denied_if_global_permission_removed(self):
        """
        If the user loses the global OIDC permission after receiving a
        refresh_token, refresh must fail with invalid_grant.
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "perm-removed-refresh",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        token_resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        body = self.assertTokenResponse(token_resp)
        refresh = body["refresh_token"]

        self.user1.user_permissions.remove(self.access_oauth)
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)

        err = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(err, dict)
        self.assertEqual("invalid_grant", err.get("error"))

    def test_token_exchange_denied_if_client_secret_invalid(self):
        """
        Confidential clients must not exchange a code
        with an invalid client_secret.
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "bad-secret",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            client_secret="WRONG_SECRET",
            expected_status=(400, 401),
        )
        body = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn(
            body.get("error"),
            {"invalid_client", "invalid_grant", "invalid_request"},
        )

    def test_userinfo_requires_bearer_token(self):
        """
        /o/userinfo/ must require Authorization: Bearer <token>.
        """
        resp = self.client.get("/o/userinfo/")
        self.assertIn(resp.status_code, (401, 403))

    def test_logout_allows_only_configured_post_logout_redirect_uri(self):
        """
        /o/logout/ should only redirect to post_logout_redirect_uri if it is allowed
        by the application allowlist (AllianceAuthApplication.post_logout_redirect_uris).
        Different DOT versions may respond with 302 or 400, but must never redirect
        to an unlisted URI.
        """
        try:
            with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
                oauth2_settings.reload()
                # Ensure app has allowed post-logout redirect
                allowed = "http://localhost/post-logout-ok/"
                denied = "http://localhost/post-logout-bad/"

                self.oauth_app.post_logout_redirect_uris = f"{allowed}"
                self.oauth_app.save()
                self.oauth_app.refresh_from_db()

                # 1) allowed URI -> should redirect there (often 302), or at least not error 500
                resp_ok = self.client.get(
                    "/o/logout/", data={"post_logout_redirect_uri": allowed}
                )
                self.assertNotEqual(500, resp_ok.status_code)

                if resp_ok.status_code in (301, 302, 303, 307, 308):
                    loc = resp_ok.headers.get("Location", "")
                    self.assertTrue(loc.startswith(allowed))

                # 2) denied URI -> must NOT redirect there
                resp_bad = self.client.get(
                    "/o/logout/", data={"post_logout_redirect_uri": denied}
                )
                self.assertNotEqual(500, resp_bad.status_code)

                if resp_bad.status_code in (301, 302, 303, 307, 308):
                    loc = resp_bad.headers.get("Location", "")
                    self.assertFalse(loc.startswith(denied))
                else:
                    # Many versions return 400 on invalid redirect uri
                    self.assertIn(resp_bad.status_code, (200, 400))
        finally:
            # Avoid leaking overridden OIDC flags into other tests.
            oauth2_settings.reload()
