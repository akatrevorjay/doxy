FROM golang:1.10

RUN apt-get update -qq \
 && apt-get install -qqy git traceroute \
 && apt-get clean

RUN go get -u -v github.com/golang/lint/golint \
 && go get -u -v github.com/Masterminds/glide \
 && go get -u -v github.com/akatrevorjay/rerun

ENV GOPACKAGE=github.com/akatrevorjay/doxy \
    APP_ROOT=/app

WORKDIR /go/src/$GOPACKAGE

ENV PATH="$APP_ROOT/image/bin:$PATH" \
    CA_PATH=/ca

COPY glide.* ./
RUN glide i

RUN ln -sfvr . "$APP_ROOT" \
 && mkdir -pv "$CA_PATH"

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
