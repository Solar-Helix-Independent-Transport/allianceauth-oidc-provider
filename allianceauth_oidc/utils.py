import logging
from collections.abc import Mapping
from typing import Any

from .app_settings import (
    ALLIANCEAUTH_OIDC_LOG_MASK_HEAD,
    ALLIANCEAUTH_OIDC_LOG_MASK_TAIL,
    ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS,
)


def app_log(
    logger: logging.Logger,
    app: object,
    msg: str,
    *args: object,
    **kwargs: Any,
) -> None:
    """
    Log at INFO level if application in debug_mode, else at DEBUG level.
    Rationale:
    - debug_mode is enabled per OAuth application so admins can diagnose issues
      safely without adding noise to production logs.
    - `.isEnabledFor()` avoids unnecessary `.log()` calls (and kwargs handling)
      when the level is disabled.
    - note: `*args` are evaluated BEFORE calling this function. If you pass
      expensive-to-compute arguments, guard them with
      `if logger.isEnabledFor(level):` at the call site. This helper preserves
      lazy message formatting.

    Args:
        logger: The logger instance to use.
        app: The application instance with a 'debug_mode' attribute.
        msg: The log message format string.
        args: Arguments to be formatted into the log message.
        kwargs: Passed to logger (e.g. extra=..., exc_info=True).
    """
    level = (
        logging.INFO if getattr(app, "debug_mode", False) else logging.DEBUG
    )
    if logger.isEnabledFor(level):
        logger.log(level, msg, *args, **kwargs)


def mask_secret(value: object, *, head: int = 2, tail: int = 2) -> str | None:
    """
    Mask a secret value by showing only the first `head`
    and last `tail` characters.
    Why masking exists: in debug scenarios you may need to confirm a secret
    is present/non-empty (or changing), but you must never log the full value.

    Args:
        value: The secret value to mask.
        head: Number of characters to show at the start.
        tail: Number of characters to show at the end.
    Returns:
        The masked secret string, or None if the input was None.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        s = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        s = value
    else:
        return f"<non-string:{type(value).__name__}>"
    if not s:
        return ""
    head = max(0, head)
    tail = max(0, tail)
    if head + tail == 0:
        return "..."
    if len(s) <= head + tail:
        return "*" * len(s)
    return f"{s[:head]}…{s[-tail:]}"


def redact_secret(value: object) -> str | None:
    """
    Return a redacted version of the secret value for logging.
    Why "<redacted>" by default:
    - it is the safest mode: it reveals neither length nor prefixes/suffixes.
    - if an admin explicitly enables masking, they accept the metadata
      leak risk (e.g., length or partial prefixes/suffixes).

    Args:
        value: The secret value to redact.
    Returns:
        Redacted secret string, or None if the input was None.
    """
    if value is None:
        return None
    if not ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS:
        return "<redacted>"
    return mask_secret(
        value,
        head=ALLIANCEAUTH_OIDC_LOG_MASK_HEAD,
        tail=ALLIANCEAUTH_OIDC_LOG_MASK_TAIL,
    )


def build_oidc_debug_meta(
    request: object,
    payload: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Build a dict safe for logging in debug_mode.
    Never returns raw token strings or secrets.
    Why we return a curated "meta" instead of logging request/response as-is:
    - the token endpoint can contain access_token/refresh_token/id_token;
      logging them would be a serious credential leak.
    - for diagnostics, grant_type/scope/client_id/redirect_uri
      plus "secret present" (redacted) is usually sufficient.
    - this helper must be "safe by construction": it always returns
      sanitized data.

    Args:
        request: The HTTP request object.
        payload: The response payload mapping.
    Returns:
        Safe dict for logging.
    """
    post = getattr(request, "POST", None)

    def post_get(key: str) -> Any:
        # request.POST may not be a QueryDict in some edge setups,
        # so we defensively check for a callable `.get()`.
        if post is None:
            return None
        getter = getattr(post, "get", None)
        return getter(key) if callable(getter) else None

    payload_dict: Mapping[str, Any] = payload or {}

    return {
        # request-side (safe)
        "grant_type": post_get("grant_type"),
        "scope": post_get("scope"),
        "client_id": post_get("client_id"),
        "redirect_uri": post_get("redirect_uri"),
        "code": redact_secret(post_get("code")),
        "refresh_token_req": redact_secret(post_get("refresh_token")),
        "client_secret": redact_secret(post_get("client_secret")),
        "assertion": redact_secret(post_get("assertion")),
        # response-side (NEVER raw)
        "token_type": payload_dict.get("token_type"),
        "expires_in": payload_dict.get("expires_in"),
        "scope_resp": payload_dict.get("scope"),
        "access_token": redact_secret(payload_dict.get("access_token")),
        "refresh_token": redact_secret(payload_dict.get("refresh_token")),
        "id_token": redact_secret(payload_dict.get("id_token")),
    }
