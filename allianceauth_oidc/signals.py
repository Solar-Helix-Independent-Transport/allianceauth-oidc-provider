import logging

from oauth2_provider import signals

from django.conf import settings

logger = logging.getLogger(__name__)


def debug_OIDC(sender, request, token, body, *args, **kwargs):
    if body:
        logger.warning(body)


signals.app_authorized.connect(debug_OIDC)
