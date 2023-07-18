from allianceauth.authentication.models import State
from oauth2_provider.models import AbstractApplication

from django.contrib.auth.models import Group
from django.db import models


class AllianceAuthApplication(AbstractApplication):
    logo = models.ImageField(blank=True, null=True)
    states = models.ManyToManyField(State, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
    active = models.BooleanField(default=True)

    def is_usable(self, request):
        """
        Determines whether the application can be used.

        :param request: The oauthlib.common.Request being processed.
        """
        return self.active

    class Meta:
        permissions = [
            ("access_oidc", "Can Authenticate External Apps with OIDC")]
