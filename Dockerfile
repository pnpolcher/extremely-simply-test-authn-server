FROM python:3.12-slim-bookworm AS build

RUN pip install --no-cache-dir poetry
RUN mkdir /app
WORKDIR /app
COPY main.py poetry.lock pyproject.toml /app/
RUN poetry config virtualenvs.create false \
    && poetry install --no-root \

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get dist-upgrade -y
RUN apt-get clean && rm -rf -- /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY . .
CMD ["python", "server.py"]