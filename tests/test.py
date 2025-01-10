from argparse import Namespace
import unittest

from fastapi.testclient import TestClient

from server import setup_app


class AuthServerTestCase(unittest.TestCase):
    def setUp(self):
        self.app, self.auth_backend = setup_app(
            Namespace(
                user_database_name=":memory:",
                algorithm="HS256",
                secret_key="mock-secret-key",
                access_token_expire_minutes=30,
            )
        )

        self.client = TestClient(self.app)

        self._setup_users()

    def _setup_users(self):
        self.auth_backend.create_user("johndoe", "Test123!")

    def test_get_users_me_not_logged_in(self):
        response = self.client.get("/users/me")
        self.assertEqual(response.status_code, 401)


    def test_login_existing_user(self):
        response = self.client.post(
            "/token",
            data={
                "username": "johndoe",
                "password": "Test123!",
            },
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

    def test_login_non_existing_user(self):
        response = self.client.post(
            "/token",
            data={
                "username": "johndoe2",
                "password": "Test123!",
            },
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        self.assertEqual(response.status_code, 401)
