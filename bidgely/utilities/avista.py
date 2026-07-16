import base64
import json
import logging
import re
from typing import Any

import aiohttp
from py3rijndael import Pkcs7Padding, RijndaelCbc

from bidgely.exceptions import InvalidAuth

from .base import UtilityBase

logger = logging.getLogger(__name__)

MYAVISTA = "https://www.myavista.com"
# appConfig.antiForgeryToken is inlined in the sign-in page's bootstrap script.
ANTI_FORGERY = re.compile(r"antiForgeryToken:\s*'([^']+)'")


def create_bidgely_payload(widget: dict[str, Any]) -> dict[str, str]:
    """Rebuild the object myavista's bidgelyloader encrypts for Bidgely."""
    payload = widget["PayLoad"]
    return {
        "utilityAccountIdentifier": payload["AccAndPremise"],
        "fuelType": payload["SAType"],
        "accountType": payload["AccountType"],
        "accessToken": payload["AuthKey"],
    }


def create_bidgely_token(widget: dict[str, Any], payload: dict[str, str]) -> str:
    """AES-256-CBC encrypt the payload with the per-session key myavista hands out.

    Rijndael with a 16 byte block is AES; AESKey and IVCode are used as raw
    ASCII, not decoded, which is what makes them 32 and 16 bytes respectively.
    """
    cipher = RijndaelCbc(
        key=widget["AESKey"].encode(),
        iv=widget["IVCode"].encode(),
        padding=Pkcs7Padding(16),
        block_size=16,
    )
    text = json.dumps(payload, separators=(",", ":")).encode()
    return base64.b64encode(cipher.encrypt(text)).decode()


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

        body = {
            "clientId": widget["ClientId"],
            "encryptedData": create_bidgely_token(
                widget, create_bidgely_payload(widget)
            ),
        }
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
