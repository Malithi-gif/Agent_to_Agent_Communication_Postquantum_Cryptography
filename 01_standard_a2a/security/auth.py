import secrets

from fastapi import Header, HTTPException, status

from config import ACCESS_TOKEN


def verify_bearer_token(authorization: str | None = Header(default=None)):
    expected = f"Bearer {ACCESS_TOKEN}"

    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True
