from django.core.exceptions import PermissionDenied
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors as oauth_errors

from .security import check_user_state_and_groups


class AllianceAuthOAuth2Validator(OAuth2Validator):
    # Extend the standard scopes to add a new "permissions" scope
    # which returns a "permissions" claim:
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope.copy()
    oidc_claim_scope.update({"groups": "profile"})

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """
        Ensure app/user policy is enforced during authorization_code exchange
        (before a token is persisted).
        """
        ok = super().validate_code(
            client_id, code, client, request, *args, **kwargs
        )
        if not ok:
            return False
        try:
            user = getattr(request, "user", None)
            if user is not None and client is not None:
                check_user_state_and_groups(user, client)
        except PermissionDenied:
            return False
        return True

    def validate_refresh_token(
        self, refresh_token, client, request, *args, **kwargs
    ):
        """
        Ensure app/user policy is enforced during refresh_token flow.
        """
        ok = super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        )
        if not ok:
            return False
        try:
            user = getattr(request, "user", None)
            if user is not None and client is not None:
                check_user_state_and_groups(user, client)
        except PermissionDenied:
            return False
        return True

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Final guard: block persistence if policy fails.
        This prevents "token issued then denied" races/500s.
        """
        try:
            user = getattr(request, "user", None)
            client = getattr(request, "client", None) or getattr(
                request, "application", None
            )
            if user is not None and client is not None:
                check_user_state_and_groups(user, client)
        except PermissionDenied:
            # Convert to OAuth error response (no 500).
            raise oauth_errors.InvalidGrantError(description="Access denied")
        return super().save_bearer_token(token, request, *args, **kwargs)

    def get_additional_claims(self, request):
        out = super().get_additional_claims(request)
        user = getattr(request, "user", None)
        if user is None:
            return out
        # email
        email = getattr(user, "email", None)
        if email is not None:
            out["email"] = email
        groups = getattr(user, "groups", None)
        profile = getattr(user, "profile", None)
        main_character = getattr(profile, "main_character", None)
        # picture (avatar)
        character_id = getattr(main_character, "character_id", None)
        if character_id:
            out["picture"] = (
                f"https://images.evetech.net/characters/{character_id}/portrait?size=128"  # noqa E501
            )
        # name
        character_name = getattr(main_character, "character_name", None)
        if character_name is not None:
            out["name"] = character_name
        # groups + state
        state = getattr(profile, "state", None)
        state_name = getattr(state, "name", None)
        if groups is None:
            groups_list = []
        else:
            groups_list = list(groups.all().values_list("name", flat=True))
        if state_name is not None:
            groups_list.append(state_name)
        if groups_list:
            out["groups"] = groups_list
        # locale
        locale = getattr(profile, "language", None)
        if locale is not None:
            out["locale"] = locale
        return out
