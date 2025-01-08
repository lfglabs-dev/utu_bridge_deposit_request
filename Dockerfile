FROM rust:1.80.0

WORKDIR /app

ARG ENV=test
ENV CONTAINER_ENV=$ENV

RUN apt-get update && apt-get install -y curl

RUN curl -L -o dotenvx.tar.gz "https://github.com/dotenvx/dotenvx/releases/latest/download/dotenvx-$(uname -s)-$(uname -m).tar.gz" \
    && tar -xzf dotenvx.tar.gz \
    && mv dotenvx /usr/local/bin \
    && rm dotenvx.tar.gz

COPY Cargo.toml .env .env.production .
COPY src ./src

RUN if [ "$CONTAINER_ENV" = "prod" ]; then \
        cargo build --release; \
    else \
        cargo build; \
    fi

EXPOSE 8082

ENV RUST_BACKTRACE=1

CMD if [ "$CONTAINER_ENV" = "prod" ]; then \
        dotenvx run -f .env.production -- ./target/release/utu_auto_claim; \
    else \
        dotenvx run -- ./target/debug/utu_auto_claim; \
    fi
