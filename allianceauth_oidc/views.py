import json
import logging

from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.signals import app_authorized
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.mixins import OAuthLibMixin

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View

log = logging.getLogger("oauth2_provider")


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
                print(
                    f"STATE User: {token.user.profile.state} APP: {print(token.application.states.all())}")
                print(
                    f"GROUP User: {token.user.groups.all()} APP: {print(token.application.groups.all())}")
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
                access_granted = True
                print(resp.context_data)
                print(request.user)
                if not access_granted:
                    return render(request, "allianceauth_oidc/denied.html", context={"reason": f"{resp.context_data.application} Access Denied", "error_code": "( 403 - Application Permission Denied )"})
            return resp
        else:
            return render(request, "allianceauth_oidc/denied.html", context={"reason": "External OAuth Denied", "error_code": "( 403 - OAuth Permission Denied )"})

    def redirect(self, redirect_to, application):
        if application is None:
            # The application can be None in case of an error during app validation
            # In such cases, fall back to default ALLOWED_REDIRECT_URI_SCHEMES
            allowed_schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
        else:
            allowed_schemes = application.get_allowed_schemes()
        return OAuth2ResponseRedirect(redirect_to, allowed_schemes)
