from typing import Final

from django.conf import settings

ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS: Final[bool] = getattr(
    settings, "ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS", False
)

ALLIANCEAUTH_OIDC_LOG_MASK_HEAD: Final[int] = getattr(
    settings, "ALLIANCEAUTH_OIDC_LOG_MASK_HEAD", 2
)

ALLIANCEAUTH_OIDC_LOG_MASK_TAIL: Final[int] = getattr(
    settings, "ALLIANCEAUTH_OIDC_LOG_MASK_TAIL", 2
)
