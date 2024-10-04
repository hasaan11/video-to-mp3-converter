import os

from fastapi import Depends, FastAPI
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pymongo import MongoClient
from schemas import GenerateTokenRequest

from auth import (
    JWTDecodeError,
    JWTEncodeError,
    JWTTokenExpiredError,
    create_jwt_token,
    decode_jwt_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="generate-jwt-token")

db_client = MongoClient(os.getenv("MONGO_DB_CONNECTION_STRING"))
db = db_client["video-to-mp3"]
collection = db["users"]


def user_exists(data: dict) -> bool:
    """Checks if a user exists by verifying from a database"""
    user = collection.find_one(
        {"username": data["username"], "password": data["password"]}
    )
    if user:
        return True
    else:
        return False


@app.post("/generate-jwt-token")
def generate_jwt_token(request_data: GenerateTokenRequest) -> JSONResponse:
    """This endpoint generates a JWT token which will be sent by the user in subsequent requests. The token is used for authentiating purposes."""

    user_data = request_data.model_dump()
    if user_exists(user_data["username"], user_data["password"]):
        del user_data["password"]
        try:
            jwt_token = create_jwt_token(user_data)
            response_payload = {
                "jwt_token": jwt_token,
                "message": "JWT Token Generated Successfully!",
            }

            return JSONResponse(content=response_payload, status_code=200)
        except JWTEncodeError as e:
            raise HTTPException(
                status_code=500, detail="Internal Server Error"
            )
    else:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password!"
        ) from None


@app.post("/authenticate-user")
def authenticate_user(token: str = Depends(oauth2_scheme)) -> JSONResponse:
    """This endpoint is used to authenticate users via the JWT token. Token is extracted from the AUthorization header of the request and then vaidated by decoding it"""

    try:
        decode_jwt_token(token)

        return JSONResponse(
            status_code=200,
            content={"message": "User authenticated successfully!"},
        )

    except JWTTokenExpiredError:
        raise HTTPException(
            status_code=401,
            detail="Your token has expired. Please generate a new token!",
        ) from None

    except JWTDecodeError:
        raise HTTPException(
            status_code=401,
            detail="Could not decode the token. This indicates potential tampering. Please generate a new token!",
        ) from None
