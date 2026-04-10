FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir bcrypt && \
    pip install --no-cache-dir -e ".[all]"

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
