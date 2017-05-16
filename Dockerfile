FROM golang:1.8

RUN go get -u -v github.com/golang/lint/golint \
 && go get -u -v github.com/Masterminds/glide \
 && go get -u -v github.com/akatrevorjay/rerun

WORKDIR /go/src/github.com/akatrevorjay/doxy

COPY glide.* ./
RUN glide i

COPY utils utils
COPY servers servers
COPY core core
COPY *.go ./

RUN go install .

CMD ["doxy"]
