import os
from datetime import datetime, timedelta

from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

from .database import SessionLocal
from .models import User


SECRET_KEY = os.getenv("JWT_SECRET")

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


def get_password_hash(password):

    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):

    return pwd_context.verify(
        plain_password,
        hashed_password
    )


def get_current_user(token: str = Depends(oauth2_scheme)):

    db = SessionLocal()

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    user = db.query(User).filter(
        User.username == username
    ).first()

    db.close()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user