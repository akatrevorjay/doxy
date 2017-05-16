FROM golang:1.8

RUN go get -u -v github.com/golang/lint/golint \
 && go get -u -v github.com/Masterminds/glide \
 && go get -u -v github.com/akatrevorjay/rerun

ENV GOPACKAGE=github.com/akatrevorjay/doxy

WORKDIR /go/src/$GOPACKAGE

COPY glide.* ./
RUN glide i

COPY utils utils
COPY servers servers
COPY core core
COPY *.go ./

RUN go install .

COPY certs certs

COPY image image


ENV APP_ROOT=/app
RUN ln -sfvr . "$APP_ROOT"
ENV PATH="$APP_ROOT/image/bin:$PATH"

ENTRYPOINT ["entrypoint"]
CMD ["doxy"]
