from oauth2_provider import views

from django.urls import re_path

from .views import AuthAuthorizationView, TokenView

app_name = "oauth2_provider"


base_urlpatterns = [
    re_path(r"^authorize/$", AuthAuthorizationView.as_view(), name="authorize"),
    re_path(r"^token/$", TokenView.as_view(), name="token"),
    re_path(r"^revoke_token/$", views.RevokeTokenView.as_view(),
            name="revoke-token"),
    re_path(r"^introspect/$", views.IntrospectTokenView.as_view(),
            name="introspect"),
]


management_urlpatterns = [
    # Token management views
    re_path(r"^authorized_tokens/$", views.AuthorizedTokensListView.as_view(),
            name="authorized-token-list"),
    re_path(
        r"^authorized_tokens/(?P<pk>[\w-]+)/delete/$",
        views.AuthorizedTokenDeleteView.as_view(),
        name="authorized-token-delete",
    ),
]

oidc_urlpatterns = [
    re_path(
        r"^\.well-known/openid-configuration/$",
        views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    re_path(r"^\.well-known/jwks.json$",
            views.JwksInfoView.as_view(), name="jwks-info"),
    re_path(r"^userinfo/$", views.UserInfoView.as_view(), name="user-info"),
    re_path(r"^logout/$", views.RPInitiatedLogoutView.as_view(),
            name="rp-initiated-logout"),
]


urlpatterns = base_urlpatterns + management_urlpatterns + oidc_urlpatterns
