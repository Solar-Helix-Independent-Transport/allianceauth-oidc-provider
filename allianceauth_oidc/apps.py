from django.apps import AppConfig

from . import __version__


class AllianceAuthOIDC(AppConfig):
    name = 'allianceauth_oidc'
    label = 'allianceauth_oidc'

    verbose_name = f"Alliance Auth OIDC v{__version__}"

    def ready(self):
        import allianceauth_oidc.signals
