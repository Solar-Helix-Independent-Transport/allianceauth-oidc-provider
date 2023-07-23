from allianceauth.authentication.models import CharacterOwnership, State
from allianceauth.eveonline.models import (
    EveAllianceInfo, EveCharacter, EveCorporationInfo,
)
from allianceauth.tests.auth_utils import AuthUtils
from oauth2_provider.generators import (
    generate_client_id, generate_client_secret,
)
from oauth2_provider.models import (
    AbstractApplication, get_access_token_model, get_application_model,
)

from django.contrib.auth.models import Group, Permission
from django.test import Client, RequestFactory, TestCase


class OIDCTestCase(TestCase):
    """
    Setup 10 fake users
    Add the standard alt/main/state spread
    Load up the permissions objects into the test class
    Create an OIDC pemkey and client
    """

    @staticmethod
    def create_char(char_id, char_name, corp=None):
        c = EveCharacter(character_id=char_id,
                         character_name=char_name,
                         corporation_id=corp.corporation_id,
                         corporation_name=corp.corporation_name,
                         corporation_ticker=corp.corporation_ticker)
        if corp.alliance:
            c.alliance_id = corp.alliance.alliance_id
            c.alliance_name = corp.alliance.alliance_name
            c.alliance_ticker = corp.alliance.alliance_ticker
        c.save()
        return c

    def setUp(cls):

        cls.corp1 = EveCorporationInfo.objects.create(corporation_id=123,
                                                      corporation_name='corporation.name1',
                                                      corporation_ticker='ABC',
                                                      ceo_id=1,
                                                      member_count=1
                                                      )
        cls.alli1 = EveAllianceInfo.objects.create(alliance_id=3,
                                                   alliance_name="alliance.names1",
                                                   alliance_ticker="TEST",
                                                   executor_corp_id=123
                                                   )
        cls.alli2 = EveAllianceInfo.objects.create(alliance_id=4,
                                                   alliance_name="alliance.names4",
                                                   alliance_ticker="TEST4",
                                                   executor_corp_id=3
                                                   )

        cls.corp2 = EveCorporationInfo.objects.create(corporation_id=2,
                                                      corporation_name='corporation.name2',
                                                      corporation_ticker='DEF',
                                                      ceo_id=2,
                                                      member_count=1,
                                                      alliance=cls.alli1
                                                      )

        cls.corp3 = EveCorporationInfo.objects.create(corporation_id=3,
                                                      corporation_name='corporation.name3',
                                                      corporation_ticker='GHI',
                                                      ceo_id=3,
                                                      member_count=1,
                                                      alliance=cls.alli2
                                                      )

        cls.corp4 = EveCorporationInfo.objects.create(corporation_id=4,
                                                      corporation_name='corporation.name4',
                                                      corporation_ticker='JKL',
                                                      ceo_id=4,
                                                      member_count=1,
                                                      alliance=cls.alli2
                                                      )

        cls.char1 = cls.create_char(1, 'character.name1', corp=cls.corp1)
        cls.char2 = cls.create_char(2, 'character.name2', corp=cls.corp1)
        cls.char3 = cls.create_char(3, 'character.name3', corp=cls.corp2)
        cls.char4 = cls.create_char(4, 'character.name4', corp=cls.corp2)
        cls.char5 = cls.create_char(5, 'character.name5', corp=cls.corp3)
        cls.char6 = cls.create_char(6, 'character.name6', corp=cls.corp3)
        cls.char7 = cls.create_char(7, 'character.name7', corp=cls.corp4)
        cls.char8 = cls.create_char(8, 'character.name8', corp=cls.corp4)
        cls.char9 = cls.create_char(9, 'character.name9', corp=cls.corp2)
        cls.char10 = cls.create_char(10, 'character.name10', corp=cls.corp2)

        cls.user1 = AuthUtils.create_user('User1')
        cls.user1.profile.main_character = cls.char1
        CharacterOwnership.objects.create(
            user=cls.user1, character=cls.char1, owner_hash="abc123")
        CharacterOwnership.objects.create(
            user=cls.user1, character=cls.char2, owner_hash="cba123")
        cls.user1.profile.save()
        State.objects.get(name="Member").member_characters.add(cls.char1)
        cls.user1.profile.refresh_from_db()

        cls.user2 = AuthUtils.create_user('User2')
        cls.user2.profile.main_character = cls.char3
        CharacterOwnership.objects.create(
            user=cls.user2, character=cls.char3, owner_hash="cba321")
        cls.user2.profile.save()
        State.objects.get(name="Blue").member_characters.add(cls.char3)
        cls.user2.profile.refresh_from_db()

        cls.user3 = AuthUtils.create_user('User3')
        cls.user3.profile.main_character = cls.char5
        CharacterOwnership.objects.create(
            user=cls.user3, character=cls.char5, owner_hash="abc432")
        CharacterOwnership.objects.create(
            user=cls.user3, character=cls.char7, owner_hash="def432")
        cls.user3.profile.save()
        cls.user3.profile.refresh_from_db()

        cls.user4 = AuthUtils.create_user('User4')
        CharacterOwnership.objects.create(
            user=cls.user4, character=cls.char9, owner_hash="def432a")
        CharacterOwnership.objects.create(
            user=cls.user4, character=cls.char10, owner_hash="def432b")

        cls.access_oauth = Permission.objects.get_by_natural_key(
            'access_oidc', 'allianceauth_oidc', 'allianceauthapplication')

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
        cls.client = Client()

        cls.test_grp = Group.objects.create(name="TestGroup")
