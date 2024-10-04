from pydantic import BaseModel


class GenerateTokenRequest(BaseModel):
    """Structure for a JWT Token request"""

    email: str
    username: str
    password: str
