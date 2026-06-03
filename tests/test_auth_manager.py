# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for OktaAuthManager token-validity / persistence behavior.

These guard the fix that lets a developer log in once instead of on every
process restart: a cached access token must be honored based on its JWT ``exp``
claim, not the in-memory ``token_timestamp`` (which resets to 0 each process).
"""

from __future__ import annotations

import time
from unittest.mock import patch

import jwt
import pytest

from okta_mcp_server.utils.auth import auth_manager as am
from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager


def _make_manager() -> OktaAuthManager:
    env = {"OKTA_ORG_URL": "https://test.okta.com", "OKTA_CLIENT_ID": "abc123"}
    with patch.dict("os.environ", env, clear=False):
        return OktaAuthManager()


def _jwt_with_exp(seconds_from_now: int) -> str:
    return jwt.encode({"exp": int(time.time()) + seconds_from_now}, "secret", algorithm="HS256")


@pytest.mark.asyncio
async def test_valid_cached_token_honored_after_process_restart():
    """A still-valid cached JWT is reused even when token_timestamp is 0 (fresh process)."""
    manager = _make_manager()
    manager.token_timestamp = 0  # simulate a freshly started process
    token = _jwt_with_exp(3000)  # ~50 min remaining

    with patch.object(am.keyring, "get_password", return_value=token), \
         patch.object(manager, "refresh_access_token") as refresh, \
         patch.object(manager, "authenticate") as authn:
        assert await manager.is_valid_token() is True
        refresh.assert_not_called()
        authn.assert_not_called()


@pytest.mark.asyncio
async def test_expired_token_triggers_refresh_then_reauth():
    """An expired token with no usable refresh token falls through to authenticate()."""
    manager = _make_manager()
    expired = _jwt_with_exp(-10)

    with patch.object(am.keyring, "get_password", return_value=expired), \
         patch.object(manager, "refresh_access_token", return_value=False) as refresh, \
         patch.object(manager, "authenticate") as authn:
        await manager.is_valid_token()
        refresh.assert_called_once()
        authn.assert_called_once()


@pytest.mark.asyncio
async def test_token_within_leeway_is_treated_expired():
    """A token expiring inside the leeway window is refreshed rather than used."""
    manager = _make_manager()
    almost = _jwt_with_exp(am.TOKEN_EXPIRY_LEEWAY - 5)

    with patch.object(am.keyring, "get_password", return_value=almost), \
         patch.object(manager, "refresh_access_token", return_value=True) as refresh, \
         patch.object(manager, "authenticate") as authn:
        await manager.is_valid_token()
        refresh.assert_called_once()
        authn.assert_not_called()


@pytest.mark.asyncio
async def test_missing_token_authenticates():
    """No cached token at all → refresh fails → authenticate()."""
    manager = _make_manager()

    with patch.object(am.keyring, "get_password", return_value=None), \
         patch.object(manager, "refresh_access_token", return_value=False), \
         patch.object(manager, "authenticate") as authn:
        await manager.is_valid_token()
        authn.assert_called_once()
