from django.urls import path, re_path
from oauth2_provider import views

from .views import AuthAuthorizationView, TokenView

app_name = "oauth2_provider"


base_urlpatterns = [
    path("authorize/", AuthAuthorizationView.as_view(), name="authorize"),
    path("token/", TokenView.as_view(), name="token"),
    path(
        "revoke_token/", views.RevokeTokenView.as_view(), name="revoke-token"
    ),
    path(
        "introspect/", views.IntrospectTokenView.as_view(), name="introspect"
    ),
]


management_urlpatterns = [
    # Token management views
    path(
        "authorized_tokens/",
        views.AuthorizedTokensListView.as_view(),
        name="authorized-token-list",
    ),
    re_path(
        r"^authorized_tokens/(?P<pk>[\w-]+)/delete/$",
        views.AuthorizedTokenDeleteView.as_view(),
        name="authorized-token-delete",
    ),
]

oidc_urlpatterns = [
    path(
        ".well-known/openid-configuration/",
        views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(
        ".well-known/jwks.json", views.JwksInfoView.as_view(), name="jwks-info"
    ),
    path("userinfo/", views.UserInfoView.as_view(), name="user-info"),
    path(
        "logout/",
        views.RPInitiatedLogoutView.as_view(),
        name="rp-initiated-logout",
    ),
]


urlpatterns = base_urlpatterns + management_urlpatterns + oidc_urlpatterns
