"""Tests for the Avista login flow."""

from typing import Any
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock

import aiohttp

from bidgely import Bidgely, CannotConnect


def _response(*, text: str = "", body: dict[str, Any] | None = None) -> MagicMock:
    request = MagicMock()
    response = request.__aenter__.return_value
    response.text = AsyncMock(return_value=text)
    response.json = AsyncMock(return_value=body)
    return request


class TestAvistaLogin(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.session = MagicMock(spec=aiohttp.ClientSession)
        self.api = Bidgely(self.session, "Avista", "test-user", "test-password", "")
        self.sign_in = _response(text="antiForgeryToken: 'test-token'")
        self.login = _response(body={"Authenticated": True})

    async def test_forwards_pre_encrypted_payload(self) -> None:
        self.session.get.side_effect = [
            self.sign_in,
            _response(body={"ClientId": "test-client", "EncryptedPayload": "ab+/cd=="}),
        ]
        self.session.post.side_effect = [
            self.login,
            _response(
                body={
                    "payload": {
                        "userProfileDetails": {"userId": "test-user-id"},
                        "tokenDetails": {"accessToken": "test-access-token"},
                    }
                }
            ),
        ]

        await self.api.async_login()

        self.session.post.assert_called_with(
            "https://avista-prodapi.bidgely.com/v2.0/web/wc-session",
            json={"clientId": "test-client", "encryptedData": "ab+/cd=="},
            headers={"Origin": "https://www.myavista.com"},
        )
        self.assertEqual(self.api.user_id, "test-user-id")
        self.assertEqual(self.api.access_token, "test-access-token")

    async def test_missing_encrypted_payload_is_a_connection_error(self) -> None:
        self.session.get.side_effect = [
            self.sign_in,
            _response(body={"ClientId": "test-client", "EncryptedPayload": None}),
        ]
        self.session.post.return_value = self.login

        with self.assertRaises(CannotConnect):
            await self.api.async_login()

        self.session.post.assert_called_once()
