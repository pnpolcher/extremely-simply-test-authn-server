from datetime import datetime, timedelta, UTC
import sqlite3
from typing import ClassVar

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import InvalidTokenError
from pydantic import BaseModel



class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# open a sqlite3 database and create it if it doesn't exist
class UserDbBackend:
    def __init__(self, database_name: str):
        self._conn = sqlite3.connect(database_name, check_same_thread=False)
        cursor = self._conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)"
        )
        self._conn.commit()

    def get_user(self, username):
        cursor = self._conn.cursor()
        cursor.execute("SELECT username, password FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user is None:
            raise InvalidUsernamePasswordError

        return User(username=user[0], password=user[1])

    def create_user(self, username: str, password: str) -> User:
        cursor = self._conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", (username, password)
        )
        self._conn.commit()
        return User(username=username, password=password)

    def delete_user(self, username):
        cursor = self._conn.cursor()
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        self._conn.commit()


class InvalidUsernamePasswordError(Exception):
    pass


class AuthenticationBackend:
    def __init__(self,
                 user_database_name: str,
                 algorithm: str,
                 secret_key: str,
                 access_token_expire_minutes: int):

        self._access_token_expire_minutes = access_token_expire_minutes
        self._algorithm = algorithm
        self._secret_key = secret_key
        self._users = UserDbBackend(user_database_name)
        self._password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def authenticate_user(self, username: str, password: str) -> User:
        user = self._users.get_user(username)

        if user and self._password_context.verify(password, user.password):
            return user
        else:
            raise InvalidUsernamePasswordError

    def create_access_token(self, data: dict, expires_delta: timedelta = None) -> str:

        jwt_dict = data.copy()

        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(minutes=self._access_token_expire_minutes)

        jwt_dict.update({"exp": expire})

        encoded_jwt = jwt.encode(jwt_dict, self._secret_key, algorithm=self._algorithm)
        return encoded_jwt

    def decode_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm]
            )
        except JWTError:
            raise InvalidTokenError

        return payload

    def create_user(self, username: str, password: str) -> User:
        hashed_password = self._password_context.hash(password)
        return self._users.create_user(username, hashed_password)

    def get_user(self, username: str) -> User:
        return self._users.get_user(username)


class AuthenticationRouter:

    oauth2_scheme: ClassVar[OAuth2PasswordBearer] = OAuth2PasswordBearer(
        tokenUrl="token",
        scopes={"me": "Read information about the current user"}
    )

    def __init__(self, auth_backend: AuthenticationBackend):
        self._auth_backend = auth_backend
        self._router = APIRouter()
        self._router.add_api_route(
            "/token",
            self.login,
            methods=["POST"],
            response_model=Token,
        )
        self._router.add_api_route(
            "/users/me",
            self.get_users_me,
            methods=["GET"],
            response_model=User,
            dependencies=[Depends(self.get_current_user)]
        )

    @property
    def router(self) -> APIRouter:
        return self._router

    async def login(self, form_data: OAuth2PasswordRequestForm = Depends()):
        try:
            user = self._auth_backend.authenticate_user(
                form_data.username,
                form_data.password
            )
        except InvalidUsernamePasswordError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )

        access_token = self._auth_backend.create_access_token(
            data={"sub": user.username},
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
        }

    def get_current_user(self, security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)) -> User:

        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = self._auth_backend.decode_token(token)
            username = payload.get("sub")
            token_scopes = payload.get("scopes", [])

            if username is None:
                raise credentials_exception
            for scope in security_scopes.scopes:
                if scope not in token_scopes:
                    raise HTTPException(
                        status_code=status.HTTP_403_UNAUTHORIZED,
                        detail="Not enough permissions",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        except InvalidTokenError:
            raise credentials_exception

        try:
            user = self._auth_backend.get_user(username)
        except InvalidUsernamePasswordError:
            raise credentials_exception

        return user

    async def get_users_me(self, current_user: User) -> User:
        print(current_user)
        return current_user
