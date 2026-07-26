import logging

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from INVENTORY.models import Agent

logger = logging.getLogger("vant-siem.aegis.auth")


class AgentTokenAuthentication(BaseAuthentication):
    """
    Authenticates agent-to-server API calls using the Bearer token
    issued during agent registration (stored in Agent.meta['auth_token']).
    """

    keyword = "Bearer"

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header:
            return None

        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0] != self.keyword:
            return None

        token = parts[1].strip()
        if not token:
            return None

        agent = Agent.objects.filter(meta__auth_token=token).first()
        if agent is None:
            raise AuthenticationFailed("Invalid agent token")

        if agent.status == "disabled":
            raise AuthenticationFailed("Agent is disabled")

        return (agent, token)
