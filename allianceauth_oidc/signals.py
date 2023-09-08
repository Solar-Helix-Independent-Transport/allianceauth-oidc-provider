import logging

from oauth2_provider import signals

from django.conf import settings

logger = logging.getLogger(__name__)


def debug_OIDC(sender, request, token, body, *args, **kwargs):
    logger.warning(body)


if getattr(settings, "OIDC_DEBUG", False):
    signals.app_authorized.connect(debug_OIDC)
