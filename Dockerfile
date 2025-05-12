FROM python:3.13-alpine

RUN apk update && apk add rustup clang make pkgconf linux-headers
RUN rustup-init -y

ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup target add x86_64-unknown-linux-musl

RUN mkdir -p /server/static/files
WORKDIR /server

COPY ./docker-scripts /docker-scripts

# Build libmnl and libnftnl manually, because cargo does not like the ones provided by Alpine.
RUN /docker-scripts/build-libmnl.sh
RUN /docker-scripts/build-libnftnl.sh

COPY ./server /server
# Install server dependencies.
RUN cd /server && pip3 install --no-cache-dir -r requirements.txt

COPY ./client/start_sploit.py /server/static/files/
COPY ./hfi /hfi-src

ENTRYPOINT ["python3", "main.py"]
