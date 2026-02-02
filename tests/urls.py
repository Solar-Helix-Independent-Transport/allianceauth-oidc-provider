import allianceauth.urls
from django.urls import include, path

from . import views

urlpatterns = allianceauth.urls.urlpatterns

urlpatterns += [
    # Navhelper test urls
    path("main-page/", views.page, name="p1"),
    path("main-page/sub-section/", views.page, name="p1-s1"),
    path("second-page/", views.page, name="p1"),
    path("o/", include("allianceauth_oidc.urls", namespace="oauth2_provider")),
]
