import logging

from django.core.exceptions import PermissionDenied

from .utils import app_log

# This module intentionally uses getattr/callable checks:
# - these functions are called from multiple places (views/validators) and must
#   tolerate partially mocked objects in tests/integrations.
# - failures should become PermissionDenied, not AttributeError.

logger = logging.getLogger(f"extensions.{__name__}")


def is_superuser(user: object) -> bool:
    """
    Helper to check if user is superuser.
    """
    return getattr(user, "is_superuser", False)


def check_user_global_oidc_access(user: object) -> None:
    """
    Global gate: user must have the allianceauth_oidc.access_oidc permission,
    unless they are superuser.
    """
    if is_superuser(user):
        logger.debug("OIDC ALLOWED: superuser user=%s", user)
        return
    has_perm = getattr(user, "has_perm", None)
    # has_perm is the standard Django contract. If it's missing, treat the
    # object as an invalid user and deny access.
    if not callable(has_perm):
        raise PermissionDenied("Invalid user object (no has_perm)")
    if not has_perm("allianceauth_oidc.access_oidc"):
        logger.warning("OIDC DENIED: missing global permission user=%s", user)
        raise PermissionDenied(
            "Missing allianceauth_oidc.access_oidc permission"
        )


def check_user_state_and_groups(user: object, app: object) -> None:
    """
    App gate:
    - If app has no states and no groups: allow.
    - If app has states and/or groups: allow if (state matches)
      OR (any group matches).
    - Superuser bypasses.
    Also enforces global permission via check_user_global_oidc_access().
    """
    check_user_global_oidc_access(user)
    if is_superuser(user):
        return

    debug_mode = getattr(app, "debug_mode", False)
    app_states = getattr(app, "states", None)
    app_groups = getattr(app, "groups", None)

    # If the application doesn't look like the expected Django OAuth Toolkit
    # model, deny rather than accidentally allowing access.
    if app_states is None or app_groups is None:
        raise PermissionDenied(
            "Invalid application object (missing states/groups)"
        )

    has_state_restrictions = app_states.exists()
    has_group_restrictions = app_groups.exists()

    # No app-level restrictions
    if not has_state_restrictions and not has_group_restrictions:
        app_log(
            logger,
            app,
            "OIDC ALLOWED: no app restrictions user=%s app=%s",
            user,
            app,
        )
        return

    state_access = False
    group_access = False

    if has_state_restrictions:
        profile = getattr(user, "profile", None)
        user_state = (
            getattr(profile, "state", None) if profile is not None else None
        )
        user_state_pk = getattr(user_state, "pk", None)
        state_access = (
            bool(user_state_pk)
            and app_states.filter(pk=user_state_pk).exists()
        )
        # list(queryset) can be expensive, so we guard it with
        # isEnabledFor(INFO). Otherwise, even with debug_mode we'd create
        # unnecessary DB load.
        if debug_mode and logger.isEnabledFor(logging.INFO):
            # In debug_mode we intentionally log at INFO
            # for admin convenience.
            logger.info(
                "OAUTH STATE: user_state=%s app_states=%s",
                user_state,
                list(app_states.values_list("name", flat=True)),
            )

    if has_group_restrictions:
        user_groups = getattr(user, "groups", None)
        if user_groups is not None:
            # Similarly: serializing group lists can be expensive,
            # so only log when INFO is enabled.
            if debug_mode and logger.isEnabledFor(logging.INFO):
                logger.info(
                    "OAUTH GROUP: user_groups=%s app_groups=%s",
                    list(user_groups.values_list("name", flat=True)),
                    list(app_groups.values_list("name", flat=True)),
                )
            user_group_ids = user_groups.values_list("id", flat=True)
            group_access = app_groups.filter(id__in=user_group_ids).exists()

    if group_access or state_access:
        reason = []
        if group_access:
            reason.append("group")
        if state_access:
            reason.append("state")
        app_log(
            logger,
            app,
            "OIDC ALLOWED: (%s access): user=%s app=%s",
            ", ".join(reason),
            user,
            app,
        )
        return

    logger.warning(
        "OIDC DENIED: app restrictions user=%s app=%s group_access=%s state_access=%s",  # noqa E501
        user,
        app,
        group_access,
        state_access,
    )
    raise PermissionDenied("User not allowed for this application")
