# Extremely simple authentication server

As its name clearly states it, this is an *extremely simple*
authentication server with the only purpose to make local
testing easier.

It stores user data and a hashed password in a [SQLite](https://www.sqlite.org/)
database. A `POST` request to the `/token` endpoint will return a signed JWT
token, if both the username and password match.

The code is loosely based on the [FastAPI documentation](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).
Eventually, it will be extended to support other features, such as
JSON Web Key Sets (JWKS), additional claims, and so on.

## License

The code is licensed under the 2.0 version of the Apache License.

## Contributions

Contributions are welcome. Feel free to fork the project and open a
pull request, or reach out to me with your idea. Just bear in mind
that this is a hobby project, and as such, I may not always have the
time to go through your PR or read your email right away. I will do
my best to reply to every PR or email that I receive, though.

## Disclaimer

This is **NOT** a production-ready authentication server.
It is not one now and it will **never** be one. Use it in
a local test environment *only* and at your own risk.
