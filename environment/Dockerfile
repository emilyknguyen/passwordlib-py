FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/emilyknguyen/passwordlib-py.git . && \
    git checkout 3def3a60fc8a9c7cb9979ade61c3c0e48be6249c

RUN pip install --no-cache-dir bcrypt && \
    pip install --no-cache-dir -e ".[all]"

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
