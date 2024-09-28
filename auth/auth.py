import logging
import os
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt

ENCODING_ALGORITHM = "HS256"


class JWTTokenExpiredError(Exception):
    """Custom exception for expired JWT tokens."""

    def __init__(self, message: str = "JWT token has expired"):
        self.message = message
        super().__init__(self.message)


class JWTDecodeError(Exception):
    """Custom exception for invalid JWT tokens."""

    def __init__(self, message: str = "Could not decode JWT token"):
        self.message = message
        super().__init__(self.message)


def create_jwt_token(user_data: dict) -> str:
    """
    Creates a JWT token based on user data.

    Args:
        user_data (dict): The user data.

    Returns:
        jwt_token (str): The token generated based on encoding algorithm and the secret key.
    """
    payload = user_data.copy()

    # Set expiration time from environment variable, default to 3600 seconds (60 minutes)
    time_delta = int(os.getenv("JWT_EXPIRATION_TIME", 3600))
    payload["exp"] = datetime.now(UTC) + timedelta(seconds=time_delta)

    try:
        jwt_token = jwt.encode(
            payload, os.getenv("JWT_TOKEN_KEY"), algorithm=ENCODING_ALGORITHM
        )
        return jwt_token
    except Exception as e:
        logging.exception(
            "Failed to encode user data as JWT token: %s", str(e)
        )
        raise JWTDecodeError()


def decode_jwt_token(jwt_token: str) -> dict:
    """
    Decodes a JWT token and returns the contents as a python dictionary

    Args:
        jwt_token (str): An encoded JWT token

    Returns:
        token_data (dict): A Python dictionary containing the contents of the og payload
    """
    try:
        token_data = jwt.decode(
            jwt_token,
            os.getenv("JWT_TOKEN_KEY"),
            algorithms=[ENCODING_ALGORITHM],
        )
    except JWTError as e:
        logging.exception("Could not decode JWT token: %s", str(e))
        raise JWTDecodeError()

    return token_data


def token_has_expired(expiration_time: int) -> bool:
    """Takes expiration time (in seconds) of a JWT token and checks if it has expired or not"""
    time_now = datetime.now(UTC).timestamp()
    if time_now >= expiration_time:
        return True
    return False


def get_current_user(jwt_token: str) -> str:
    """Calls the decode_jwt_token function and returns the username of the user."""
    token_data = decode_jwt_token(jwt_token)
    if token_has_expired(token_data["exp"]):
        raise JWTTokenExpiredError

    return token_data["username"]
