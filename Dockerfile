FROM golang:latest AS build

WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /happyfarm .



FROM golang:latest

RUN apt-get update && apt-get install -y \
    clang make pkg-config linux-headers-amd64 curl python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"
RUN rustup target add x86_64-unknown-linux-musl

RUN mkdir -p /server/static/files
WORKDIR /server

COPY --from=build /happyfarm /server/happyfarm
COPY ./docker-scripts /docker-scripts
COPY ./client/start_sploit.py /server/static/files/
COPY ./hfi /hfi-src

ENTRYPOINT ["/server/happyfarm"]
