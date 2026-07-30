from django.urls import path
from auth_app.views import (
    LoginView, RefreshView, LogoutView, TokenValidateView,
    AgentRegisterView, AgentTokenCreateView, AgentValidateView, AgentRevokeView,
    UserListView, UserMeView, UserCreateView, UserUpdateView,
    UserDeleteView, UserResetPasswordView, UserChangePasswordView,
    HealthView,
)

urlpatterns = [
    path("api/login/", LoginView.as_view(), name="login"),
    path("api/refresh/", RefreshView.as_view(), name="refresh"),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/validate/", TokenValidateView.as_view(), name="token_validate"),
    path("api/agent/register/", AgentRegisterView.as_view(), name="agent_register"),
    path("api/agent/token/create/", AgentTokenCreateView.as_view(), name="agent_token_create"),
    path("api/agent/validate/", AgentValidateView.as_view(), name="agent_validate"),
    path("api/agent/revoke/", AgentRevokeView.as_view(), name="agent_revoke"),
    path("api/users/", UserListView.as_view(), name="user_list"),
    path("api/users/me/", UserMeView.as_view(), name="user_me"),
    path("api/users/create/", UserCreateView.as_view(), name="user_create"),
    path("api/users/<int:user_id>/", UserUpdateView.as_view(), name="user_update"),
    path("api/users/<int:user_id>/delete/", UserDeleteView.as_view(), name="user_delete"),
    path("api/users/<int:user_id>/reset-password/", UserResetPasswordView.as_view(), name="user_reset_password"),
    path("api/users/change-password/", UserChangePasswordView.as_view(), name="user_change_password"),
    path("api/health/", HealthView.as_view(), name="health"),
]
