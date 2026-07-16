FROM golang:latest

RUN apt-get update && apt-get install -y \
    clang \
    make \
    pkg-config \
    linux-headers-amd64 \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup target add x86_64-unknown-linux-musl

RUN mkdir -p /server/static/files
WORKDIR /server

COPY ./docker-scripts /docker-scripts
COPY ./server /server

COPY ./client/start_sploit.py /server/static/files/
COPY ./hfi /hfi-src

ENTRYPOINT ["go", "run", "."]
