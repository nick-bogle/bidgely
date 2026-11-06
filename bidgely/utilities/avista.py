import logging
import re

import aiohttp

from bidgely.exceptions import CannotConnect, InvalidAuth

from .base import UtilityBase

logger = logging.getLogger(__name__)

MYAVISTA = "https://www.myavista.com"
# appConfig.antiForgeryToken is inlined in the sign-in page's bootstrap script.
ANTI_FORGERY = re.compile(r"antiForgeryToken:\s*'([^']+)'")


class Avista(UtilityBase):
    "Avista Utilities."

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Avista"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    def api_url() -> str:
        """Return the base URL of the utility's Bidgely API host."""
        return "https://avista-prodapi.bidgely.com"

    @staticmethod
    def usage_endpoint() -> str:
        """Return the dashboard endpoint serving usage chart reads."""
        return "usage-chart-details"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        account_id: str,
    ) -> tuple[str, str]:
        """Returns user-id and token for Bidgely.

        account_id is unused: getBidgelyWidgetData returns whichever account is
        active in the myavista session.
        """
        async with session.get(f"{MYAVISTA}/sign-in") as resp:
            match = ANTI_FORGERY.search(await resp.text())
        if match is None:
            logger.debug("No anti-forgery token found on the sign-in page")
            raise InvalidAuth
        h = {"RequestVerificationToken": match.group(1)}

        body = {"username": username, "password": password, "verificationToken": ""}
        async with session.post(
            f"{MYAVISTA}/account/login", json=body, headers=h
        ) as resp:
            login = await resp.json()
        if not login.get("Authenticated"):
            logger.debug(f"Avista login failed for {username}")
            raise InvalidAuth

        async with session.get(
            f"{MYAVISTA}/bidgely/getBidgelyWidgetData", headers=h
        ) as resp:
            widget = await resp.json()

        if not isinstance(widget, dict):
            raise CannotConnect("Avista returned an invalid Bidgely widget response")

        client_id = widget.get("ClientId")
        encrypted_payload = widget.get("EncryptedPayload")
        if (
            not isinstance(client_id, str)
            or not client_id
            or not isinstance(encrypted_payload, str)
            or not encrypted_payload
        ):
            raise CannotConnect(
                "Avista did not return a valid Bidgely client ID or encrypted payload"
            )

        body = {"clientId": client_id, "encryptedData": encrypted_payload}
        # wc-session 400s unless the Origin is one Bidgely has whitelisted.
        async with session.post(
            f"{Avista.api_url()}/v2.0/web/wc-session",
            json=body,
            headers={"Origin": MYAVISTA},
        ) as resp:
            sso = await resp.json()
        if sso.get("error"):
            logger.debug(f"Bidgely login failed for {username}: {sso['error']}")
            raise InvalidAuth

        user_id = sso["payload"]["userProfileDetails"]["userId"]
        bearer_token = sso["payload"]["tokenDetails"]["accessToken"]
        logger.debug(f"Successful token retrieved for user-id: {user_id}")

        return (user_id, bearer_token)
