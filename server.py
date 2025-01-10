import argparse
from argparse import Namespace
import os

import uvicorn
from fastapi import FastAPI

from main import AuthenticationRouter, AuthenticationBackend


app = FastAPI()


def setup_app(args: Namespace) -> (FastAPI, AuthenticationBackend):
    authentication_backend = AuthenticationBackend(
        user_database_name=args.user_database_name,
        algorithm=args.algorithm,
        secret_key=args.secret_key,
        access_token_expire_minutes=args.access_token_expire_minutes,
    )
    authentication_router = AuthenticationRouter(authentication_backend)
    app.include_router(authentication_router.router)

    return app, authentication_backend


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a string parameter.")

    parser.add_argument(
        "--user-database-name",
        type=str,
        required=False,
        default=os.environ.get("USER_DATABASE_NAME", "users.db"),
        help="A string parameter to process.",
    )
    parser.add_argument(
        "--algorithm",
        type=str,
        required=False,
        default=os.environ.get("ALGORITHM", "HS256"),
        help="A string parameter to process.",
    )
    parser.add_argument(
        "--access-token-expire-minutes",
        type=int,
        required=False,
        default=int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30)),
        help="A string parameter to process.",
    )
    parser.add_argument(
        "--secret-key",
        type=str,
        required=False,
        default=os.environ.get("SECRET_KEY", "mock-secret-key"),
        help="A string parameter to process.",
    )

    args = parser.parse_args()
    setup_app(args)
    uvicorn.run(app, host="0.0.0.0", port=8000)
