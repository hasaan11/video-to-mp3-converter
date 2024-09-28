import os
from datetime import UTC, datetime

import pytest

from auth.auth import (JWTDecodeError, JWTTokenExpiredError, create_jwt_token,
                      decode_jwt_token, get_current_user)

os.environ["JWT_TOKEN_KEY"] = "test_secret"
os.environ["JWT_EXPIRATION_TIME"] = "3600"


def test_create_jwt_token():
    user_data = {"username": "test_user", "email": "test_user@example.com"}
    token = create_jwt_token(user_data)

    assert isinstance(token, str)
    assert len(token) > 0

    decoded_data = decode_jwt_token(token)
    assert decoded_data["username"] == user_data["username"]
    assert decoded_data["email"] == user_data["email"]
    assert "exp" in decoded_data


def test_decode_jwt_token_invalid():
    with pytest.raises(JWTDecodeError):
        decode_jwt_token("invalid_token")
