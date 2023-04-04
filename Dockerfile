FROM python:3.11-slim

WORKDIR /app
COPY poetry.lock pyproject.toml ./

RUN pip install 'poetry==1.3.1' \
    && poetry config virtualenvs.create false \
    && poetry config experimental.new-installer false \
    && poetry install --only main --no-interaction  --no-ansi --no-root

COPY . /app
CMD ["python", "phishing_catcher/catch_phishing.py"]
