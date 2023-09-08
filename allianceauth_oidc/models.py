from allianceauth.authentication.models import State
from oauth2_provider.models import AbstractApplication

from django.contrib.auth.models import Group
from django.db import models


class AllianceAuthApplication(AbstractApplication):
    logo_url = models.TextField(max_length=1024, blank=True, null=True,
                                help_text="Url to the Applications Icon (128x128), can be a local static file or a full URL")
    states = models.ManyToManyField(State, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
    active = models.BooleanField(default=True)
    debug_mode = models.BooleanField(
        default=False, help_text="Prints token-post request to logging for debuging purposes. These logs are at the Warning Level.")

    def is_usable(self, request):
        """
        Determines whether the application can be used.

        :param request: The oauthlib.common.Request being processed.
        """
        return self.active

    class Meta:
        permissions = [
            ("access_oidc", "Can Authenticate External Apps with OIDC")]
