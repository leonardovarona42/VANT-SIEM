from django.urls import path
from auth_app.views import (
    LoginView,
    RefreshView,
    LogoutView,
    TokenValidateView,
    AgentRegisterView,
    AgentValidateView,
    AgentRevokeView,
    UserListView,
    UserMeView,
    UserCreateView,
    UserDeleteView,
    HealthView,
)

urlpatterns = [
    path("api/login/", LoginView.as_view(), name="login"),
    path("api/refresh/", RefreshView.as_view(), name="refresh"),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/validate/", TokenValidateView.as_view(), name="token_validate"),
    path("api/agent/register/", AgentRegisterView.as_view(), name="agent_register"),
    path("api/agent/validate/", AgentValidateView.as_view(), name="agent_validate"),
    path("api/agent/revoke/", AgentRevokeView.as_view(), name="agent_revoke"),
    path("api/users/", UserListView.as_view(), name="user_list"),
    path("api/users/me/", UserMeView.as_view(), name="user_me"),
    path("api/users/create/", UserCreateView.as_view(), name="user_create"),
    path("api/users/<int:user_id>/", UserDeleteView.as_view(), name="user_delete"),
    path("api/health/", HealthView.as_view(), name="health"),
]
