import json
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlparse

from allianceauth.authentication.models import (
    CharacterOwnership,
    EveAllianceInfo,
    EveCharacter,
    EveCorporationInfo,
    State,
)
from allianceauth.tests.auth_utils import AuthUtils
from django.contrib.auth.models import Group, Permission, User
from django.test import RequestFactory, TestCase
from oauth2_provider.generators import (
    generate_client_id,
    generate_client_secret,
)
from oauth2_provider.models import get_application_model


class OIDCTestCase(TestCase):
    """
    Shared test helpers and test data for OIDC provider tests.
    """

    alliances: ClassVar[list[EveAllianceInfo]]
    corps: ClassVar[list[EveCorporationInfo]]
    characters: ClassVar[list[EveCharacter]]
    users: ClassVar[list[User]]

    def grant_oidc_access(self, user: User) -> None:
        """
        Grant the global OIDC permission to a user.
        """
        user.user_permissions.add(self.access_oauth)
        user.refresh_from_db()

    def assertDenied(self, response: Any, user: User) -> None:
        """
        Assert that response is the standard denied page for the given user.
        """
        self.assertEqual(403, response.status_code)
        self.assertTemplateUsed(response, "allianceauth_oidc/denied.html")
        self.assertIn('User "', response.context["reason"])
        self.assertIn(str(user), response.context["reason"])

    def assertDeniedGlobal(self, response: Any, user: User) -> None:
        """
        Assert that the denial reason is the global permission gate.
        """
        self.assertDenied(response, user)
        self.assertIn(
            "has no permission to use OIDC applications",
            response.context["reason"],
        )
        self.assertIn(
            "User not allowed global OIDC access",
            response.context["error_code"],
        )

    def assertDeniedApp(self, response: Any, user: User, app: Any) -> None:
        """
        Assert that the denial reason is application policy (state/groups).
        """
        self.assertDenied(response, user)
        self.assertIn(
            "has no permission to use application", response.context["reason"]
        )
        self.assertIn(str(app), response.context["reason"])
        self.assertIn(
            "User not allowed for this application",
            response.context["error_code"],
        )

    def assertAuthorizePage(
        self, response: Any, app: Any, scopes: list[str] | None = None
    ) -> None:
        """
        Assert that the authorization consent page rendered for the given app.
        """
        self.assertEqual(200, response.status_code)
        self.assertTemplateUsed(response, "allianceauth_oidc/authorize.html")
        self.assertIn("application", response.context)
        self.assertEqual(app, response.context["application"])
        if scopes is not None:
            got = response.context.get("scopes")
            self.assertIsInstance(got, (list, tuple))
            self.assertEqual(sorted(scopes), sorted(list(got)))

    def parse_redirect(
        self,
        response: Any,
        status_codes: tuple[int, ...] = (301, 302, 303, 307, 308),
    ) -> tuple[str, str, dict[str, list[str]]]:
        """
        Parses a redirect response from the authorize endpoint.
        Returns (location, path, parsed_qs_dict).
        """
        self.assertIn(response.status_code, status_codes)
        self.assertIn("Location", response.headers)
        loc = response.headers["Location"]
        parsed = urlparse(loc)
        path = parsed.path
        qs = parse_qs(parsed.query)
        return (loc, path, qs)

    def authorize_get(self, user: User, params: dict | None = None) -> Any:
        self.client.force_login(user)
        return self.client.get("/o/authorize/", data=(params or {}))

    def authorize_post(self, user: User, data: dict | None = None) -> Any:
        self.client.force_login(user)
        return self.client.post("/o/authorize/", data=(data or {}))

    def authorize_post_and_extract_code(
        self, user: User, data: dict, expected_redirect_uri: str | None = None
    ) -> tuple[str, str, dict]:
        """
        POST /o/authorize/ (allow=True) -> redirect to redirect_uri
        with code+state.
        """
        resp = self.authorize_post(user, data=data)
        loc, _, qs = self.parse_redirect(resp, (302,))

        if expected_redirect_uri is not None:
            got = urlparse(loc)
            exp = urlparse(expected_redirect_uri)
            self.assertEqual(
                (exp.scheme, exp.netloc), (got.scheme, got.netloc)
            )
            self.assertTrue(got.path.startswith(exp.path))

        self.assertIn("code", qs)
        self.assertIn("state", qs)

        resp_code = qs["code"][0]
        resp_state = qs["state"][0]

        self.assertIsInstance(resp_code, str)
        self.assertIsInstance(resp_state, str)

        if "state" in data:
            self.assertEqual(data["state"], resp_state)

        return resp_code, loc, qs

    def exchange_code_for_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        state: str | None = None,
        scope: str | None = None,
        expected_status: int | tuple[int, ...] = 200,
    ) -> Any:
        """
        Exchange authorization code for a token response.
        """
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id or self.oauth_id,
            "redirect_uri": redirect_uri,
            "client_secret": client_secret or self.oauth_secret,
            "code": code,
        }
        if state is not None:
            payload["state"] = state
        if scope is not None:
            payload["scope"] = scope
        resp = self.client.post("/o/token/", data=payload)
        if isinstance(expected_status, tuple):
            self.assertIn(resp.status_code, expected_status)
        else:
            self.assertEqual(expected_status, resp.status_code)
        return resp

    def refresh_token(
        self,
        *,
        refresh_token: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str | None = None,
        expected_status: int | tuple[int, ...] = 200,
    ) -> Any:
        """
        Exchange refresh_token for a new token response.
        """
        payload = {
            "grant_type": "refresh_token",
            "client_id": client_id or self.oauth_id,
            "client_secret": client_secret or self.oauth_secret,
            "refresh_token": refresh_token,
        }
        if scope is not None:
            payload["scope"] = scope

        resp = self.client.post("/o/token/", data=payload)
        if isinstance(expected_status, tuple):
            self.assertIn(resp.status_code, expected_status)
        else:
            self.assertEqual(expected_status, resp.status_code)
        return resp

    def assertOAuthError(
        self,
        response: Any,
        *,
        expected_error: str,
    ) -> Any:
        """
        Assert that the response body is an OAuth2 error payload.
        """
        body = json.loads(response.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertEqual(expected_error, body.get("error"))
        return body

    def assertTokenResponse(
        self,
        response: Any,
        *,
        expected_scope: str | None = None,
        expected_expires_in: int | None = None,
    ) -> Any:
        """
        Assert that a successful token response contains required fields.
        """
        body = json.loads(response.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn("access_token", body)
        self.assertIn("refresh_token", body)
        self.assertIn("id_token", body)

        if expected_scope is not None:
            got = body.get("scope") or ""
            self.assertEqual(set(expected_scope.split()), set(got.split()))

        if expected_expires_in is not None:
            self.assertEqual(expected_expires_in, body.get("expires_in"))

        return body

    @staticmethod
    def create_char(
        char_id: int, char_name: str, corp: EveCorporationInfo
    ) -> EveCharacter:
        """
        Create a character row with corp/alliance fields denormalized.
        """
        return EveCharacter.objects.create(
            character_id=char_id,
            character_name=char_name,
            corporation_id=corp.corporation_id,
            corporation_name=corp.corporation_name,
            corporation_ticker=corp.corporation_ticker,
            alliance_id=getattr(corp.alliance, "alliance_id", None),
            alliance_name=getattr(corp.alliance, "alliance_name", None),
            alliance_ticker=getattr(corp.alliance, "alliance_ticker", None),
        )

    @classmethod
    def setUpTestData(cls) -> None:
        # Alliances / corps / characters / users are shared across tests.
        cls.alli1 = EveAllianceInfo.objects.create(
            alliance_id=3,
            alliance_name="alliance.names1",
            alliance_ticker="TEST",
            executor_corp_id=123,
        )
        cls.alli2 = EveAllianceInfo.objects.create(
            alliance_id=4,
            alliance_name="alliance.names4",
            alliance_ticker="TEST4",
            executor_corp_id=3,
        )
        cls.alliances = [cls.alli1, cls.alli2]

        cls.corp1 = EveCorporationInfo.objects.create(
            corporation_id=123,
            corporation_name="corporation.name1",
            corporation_ticker="ABC",
            ceo_id=1,
            member_count=1,
        )
        cls.corp2 = EveCorporationInfo.objects.create(
            corporation_id=2,
            corporation_name="corporation.name2",
            corporation_ticker="DEF",
            ceo_id=2,
            member_count=1,
            alliance=cls.alli1,
        )
        cls.corp3 = EveCorporationInfo.objects.create(
            corporation_id=3,
            corporation_name="corporation.name3",
            corporation_ticker="GHI",
            ceo_id=3,
            member_count=1,
            alliance=cls.alli2,
        )
        cls.corp4 = EveCorporationInfo.objects.create(
            corporation_id=4,
            corporation_name="corporation.name4",
            corporation_ticker="JKL",
            ceo_id=4,
            member_count=1,
            alliance=cls.alli2,
        )
        cls.corps = [cls.corp1, cls.corp2, cls.corp3, cls.corp4]

        cls.char1 = cls.create_char(1, "character.name1", corp=cls.corp1)
        cls.char2 = cls.create_char(2, "character.name2", corp=cls.corp1)
        cls.char3 = cls.create_char(3, "character.name3", corp=cls.corp2)
        cls.char4 = cls.create_char(4, "character.name4", corp=cls.corp2)
        cls.char5 = cls.create_char(5, "character.name5", corp=cls.corp3)
        cls.char6 = cls.create_char(6, "character.name6", corp=cls.corp3)
        cls.char7 = cls.create_char(7, "character.name7", corp=cls.corp4)
        cls.char8 = cls.create_char(8, "character.name8", corp=cls.corp4)
        cls.char9 = cls.create_char(9, "character.name9", corp=cls.corp2)
        cls.char10 = cls.create_char(10, "character.name10", corp=cls.corp2)
        cls.characters = [
            cls.char1,
            cls.char2,
            cls.char3,
            cls.char4,
            cls.char5,
            cls.char6,
            cls.char7,
            cls.char8,
            cls.char9,
            cls.char10,
        ]

        cls.user1 = AuthUtils.create_user("User1")
        cls.user1.profile.main_character = cls.char1
        cls.user1.profile.save()
        CharacterOwnership.objects.bulk_create(
            [
                CharacterOwnership(
                    user=cls.user1, character=cls.char1, owner_hash="abc123"
                ),
                CharacterOwnership(
                    user=cls.user1, character=cls.char2, owner_hash="cba123"
                ),
            ]
        )
        State.objects.get(name="Member").member_characters.add(cls.char1)

        cls.user2 = AuthUtils.create_user("User2")
        cls.user2.profile.main_character = cls.char3
        cls.user2.profile.save()
        CharacterOwnership.objects.create(
            user=cls.user2, character=cls.char3, owner_hash="cba321"
        )
        State.objects.get(name="Blue").member_characters.add(cls.char3)

        cls.user3 = AuthUtils.create_user("User3")
        cls.user3.profile.main_character = cls.char5
        cls.user3.profile.save()
        CharacterOwnership.objects.bulk_create(
            [
                CharacterOwnership(
                    user=cls.user3, character=cls.char5, owner_hash="abc432"
                ),
                CharacterOwnership(
                    user=cls.user3, character=cls.char7, owner_hash="def432"
                ),
            ]
        )

        cls.user4 = AuthUtils.create_user("User4")
        CharacterOwnership.objects.bulk_create(
            [
                CharacterOwnership(
                    user=cls.user4, character=cls.char9, owner_hash="def432a"
                ),
                CharacterOwnership(
                    user=cls.user4, character=cls.char10, owner_hash="def432b"
                ),
            ]
        )
        cls.users = [cls.user1, cls.user2, cls.user3, cls.user4]

        cls.access_oauth = Permission.objects.get_by_natural_key(
            "access_oidc", "allianceauth_oidc", "allianceauthapplication"
        )

        cls.oauth_secret = generate_client_secret()
        cls.oauth_id = generate_client_id()
        cls.oauth_app = get_application_model().objects.create(
            user=cls.user1,
            client_id=cls.oauth_id,
            redirect_uris="http://localhost/redir/",
            client_type="confidential",
            authorization_grant_type="authorization-code",
            client_secret=cls.oauth_secret,
            name=f"TEST APP - {cls.oauth_id}",
            skip_authorization=False,
            algorithm="RS256",
        )

        cls.factory = RequestFactory()
        cls.test_grp = Group.objects.create(name="TestGroup")
        cls.test_grp_2 = Group.objects.create(name="TestGroup2")

    def setUp(self) -> None:
        for u in self.users:
            u.refresh_from_db()
            if hasattr(u, "_prefetched_objects_cache"):
                u._prefetched_objects_cache = {}
        self.oauth_app.refresh_from_db()
        if hasattr(self.oauth_app, "_prefetched_objects_cache"):
            self.oauth_app._prefetched_objects_cache = {}

        self.client.logout()
