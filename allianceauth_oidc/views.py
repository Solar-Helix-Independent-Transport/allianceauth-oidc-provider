import json
import logging

from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import (
    get_access_token_model, get_application_model,
)
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.signals import app_authorized
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.mixins import OAuthLibMixin

from django.contrib import messages
from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View

log = logging.getLogger(__name__)


def check_user_state_and_groups(user: User, app):
    if user.is_superuser:
        log.debug(f"{user} is SU allowing full access")
        return
    group_access = True
    state_access = True
    if app.states.count():
        log.debug(
            f"OAUTH STATE User: {user.profile.state} APP: {app.states.all()}")
        state_access = app.states.filter(name=user.profile.state).exists()
    if app.groups.count():
        log.debug(
            f"OAUTH GROUP User: {user.groups.all()} APP: {app.groups.all()}")
        group_access = app.groups.filter(
            name__in=user.groups.all().values_list('name', flat=True)).exists()

    if not group_access or not state_access:
        log.warning(
            f"OAUTH {user} - {app} - Group: {group_access} State: {state_access}")
        raise PermissionDenied()


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens for anyone who meets the requirements of the application

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials
    """
    @method_decorator(sensitive_post_parameters("password"))
    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_token_response(request)
        if status == 200:
            access_token = json.loads(body).get("access_token")
            if access_token is not None:
                token = get_access_token_model().objects.get(token=access_token)
                check_user_state_and_groups(token.user, token.application)
                app_authorized.send(sender=self, request=request, token=token)

        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class AuthAuthorizationView(AuthorizationView):
    template_name = "oauth2_provider/authorize.html"

    def get(self, request, *args, **kwargs):
        if request.user.has_perm("allianceauth_oidc.access_oidc"):
            resp = super().get(request, *args, **kwargs)
            if hasattr(resp, 'context_data'):
                try:
                    check_user_state_and_groups(
                        request.user, resp.context_data['application'])
                except PermissionDenied as e:
                    log.warning(
                        f"OAUTH - {request.user} - {resp.context_data['application']} - Access Denied")
                    return render(request, "allianceauth_oidc/denied.html", context={"reason": f"{resp.context_data['application']} Access Denied", "error_code": "( 403 - Application Permission Denied )"})
            return resp
        else:
            log.warning(f"OAUTH - {request.user} - global - Access Denied")
            return render(request, "allianceauth_oidc/denied.html", context={"reason": "External OAuth Denied", "error_code": "( 403 - OAuth Permission Denied )"})
