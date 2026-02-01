import logging
from collections.abc import Mapping
from typing import Any

from django.dispatch import Signal

logger = logging.getLogger(f"extensions.{__name__}")

# Custom signal instead of direct logging inside TokenView:
# - TokenView is responsible for protocol/response, while auditing
#   is a separate concern.
# - signals make it easier to swap handlers, test, and/or forward events
#   to SIEM/audit sinks without changing the core token issuance logic.
# - use_caching=True helps when emitting frequently: Django caches
#   the receiver list.
oidc_token_issued = Signal(use_caching=True)


def audit_oidc_token_issued(
    sender: object,
    request: object,
    token: object,
    body: Mapping[str, Any] | None = None,
    *args: Any,
    **kwargs: Any,
) -> None:
    """
    Security note:
    Do NOT log OAuth token responses (access/refresh/id tokens).
    Only log minimal metadata for auditing.

    Why we never log tokens, even in debug_mode:
    - access_token/refresh_token/id_token are effectively passwords
      for their lifetime.
    - logs often end up in centralized systems/backups and outlive
      the token itself, which increases compromise risk.
    """
    try:
        app = getattr(token, "application", None)
        user = getattr(token, "user", None)
        meta = None
        if body:
            meta = {k: body.get(k) for k in ("grant_type", "scope")}
            meta = {k: v for k, v in meta.items() if v is not None} or None
        logger.info(
            "OIDC token issued client_id=%s app_id=%s user_id=%s username=%s scope=%s meta=%s",  # noqa 501
            getattr(app, "client_id", None),
            getattr(app, "id", None),
            getattr(user, "id", None),
            getattr(user, "username", None),
            getattr(token, "scope", None),
            meta,
        )
    except Exception:
        # Never fail the auth flow because of logging.
        logger.exception("Failed to audit OIDC token issuance")


oidc_token_issued.connect(
    audit_oidc_token_issued,
    dispatch_uid="allianceauth_oidc.audit_oidc_token_issued",
)
