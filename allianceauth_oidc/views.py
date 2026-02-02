import json
import logging
from typing import Any

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View
from oauth2_provider.models import (
    AbstractApplication,
    get_access_token_model,
    get_application_model,
)
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.mixins import OAuthLibMixin

from .security import (
    check_user_global_oidc_access,
    check_user_state_and_groups,
)
from .signals import oidc_token_issued
from .utils import app_log, build_oidc_debug_meta

logger = logging.getLogger(f"extensions.{__name__}")


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens
    for anyone who meets the requirements of the application

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials

    Why csrf_exempt:
    - this is a machine-to-machine endpoint; authentication happens via OAuth2
      parameters/headers, not via browser cookie sessions.
    - CSRF protection targets browser form submissions with cookies.
      Still, we must NOT log secrets and must not mix cookie auth with token
      issuance.
    """

    @method_decorator(sensitive_post_parameters("password"))
    def post(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        _, headers, body, status = self.create_token_response(request)
        # Access enforcement is handled in the OAuth2 validator
        # before token persistence.
        # Here we only emit a safe audit signal (no token strings in logs).
        if status == 200:
            try:
                # Response body can be str/bytes/non-JSON in edge cases.
                # We parse it only to build safe debug metadata and to obtain
                # access_token in order to fetch the persisted token model
                # (app/user/scope) without logging any raw tokens.
                payload = json.loads(body) if body else {}
                if not isinstance(payload, dict):
                    payload = {}
                access_token = payload.get("access_token")
                if access_token:
                    token = get_access_token_model().objects.get(
                        token=access_token
                    )
                    app = getattr(token, "application", None)
                    if getattr(
                        app, "debug_mode", False
                    ) and logger.isEnabledFor(logging.INFO):
                        # meta is computed ONLY when we really intend to log it
                        # build_oidc_debug_meta reads sanitized fields
                        # from request.POST
                        logger.info(
                            "OIDC DEBUG token issued app_id=%s client_id=%s user_id=%s meta=%s",  # noqa E501
                            getattr(app, "id", None),
                            getattr(app, "client_id", None),
                            getattr(getattr(token, "user", None), "id", None),
                            build_oidc_debug_meta(request, payload),
                        )
                    oidc_token_issued.send(
                        sender=self,
                        request=request,
                        token=token,
                        body={
                            "grant_type": request.POST.get("grant_type"),
                            "scope": request.POST.get("scope"),
                        },
                    )
            except Exception as exc:
                # Never break token issuance due to auditing/logging errors.
                logger.exception(
                    "Failed to emit OIDC audit signal for token issuance: %s",
                    exc,
                )

        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


@method_decorator(login_required, name="dispatch")
class AuthAuthorizationView(AuthorizationView):
    template_name = "allianceauth_oidc/authorize.html"

    def _get_app(self, request: HttpRequest) -> AbstractApplication | None:
        """
        Retrieve the OAuth2 Application object by client_id
        from GET or POST parameters.

        Args:
            request (HttpRequest): The user's HTTP request.

        Returns:
            AbstractApplication | None: Application instance if found,
            otherwise None.
        """
        client_id = request.GET.get("client_id") or request.POST.get(
            "client_id"
        )
        if not client_id:
            return None
        return (
            get_application_model().objects.filter(client_id=client_id).first()
        )

    def _access_denied_response(
        self, request: HttpRequest, reason: str, error_message: str
    ) -> HttpResponseBase:
        return render(
            request,
            "allianceauth_oidc/denied.html",
            context={
                "reason": reason,
                "error_code": f"(403 - {error_message})",
            },
            status=403,
        )

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        # IMPORTANT: must run for BOTH GET and POST to prevent POST-bypass.
        # Why in dispatch():
        # - Django OAuth Toolkit AuthorizationView may handle GET/POST
        #   differently.
        # - if checks are only in get()/post(), it's easy to miss a code path.
        user = getattr(request, "user", None)
        try:
            check_user_global_oidc_access(user)
        except PermissionDenied:
            logger.warning(
                "OIDC DENIED: global access user=%s path=%s method=%s",
                user,
                getattr(request, "path", None),
                getattr(request, "method", None),
            )
            return self._access_denied_response(
                request,
                f'User "{user}" has no permission to use OIDC applications.',
                "User not allowed global OIDC access",
            )

        app = self._get_app(request)
        if app is not None:
            try:
                check_user_state_and_groups(user, app)
            except PermissionDenied:
                logger.warning(
                    "OIDC DENIED: app restrictions user=%s app=%s client_id=%s path=%s method=%s",  # noqa E501
                    user,
                    app,
                    getattr(app, "client_id", None),
                    getattr(request, "path", None),
                    getattr(request, "method", None),
                )
                return self._access_denied_response(
                    request,
                    f'User "{user}" has no permission to use application "{app}".',  # noqa E501
                    "User not allowed for this application",
                )
        app_log(
            logger,
            app,
            "OIDC ALLOWED: user=%s app=%s path=%s method=%s",
            user,
            app,
            getattr(request, "path", None),
            getattr(request, "method", None),
        )
        return super().dispatch(request, *args, **kwargs)
