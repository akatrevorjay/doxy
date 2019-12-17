FROM golang:1.13

RUN apt-get update -qq \
 && apt-get install -qqy git traceroute \
 && apt-get clean

RUN go get -u -v github.com/akatrevorjay/rerun

ENV APP_ROOT=/app

WORKDIR $APP_ROOT

ENV PATH="$APP_ROOT/image/bin:$PATH" \
    CA_PATH=/ca

RUN mkdir -pv "$CA_PATH"

COPY go.mod go.sum ./
COPY vendor vendor

COPY utils utils
COPY servers servers
COPY core core
COPY *.go ./

RUN go install .

COPY image image

ENTRYPOINT ["entrypoint"]
CMD ["doxy"]

# CI docker is currently too old for this. Enable later,
#HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost/doxy-healthcheck || exit 1
