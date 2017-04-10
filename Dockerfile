FROM golang:1.8

RUN go get -u -v github.com/golang/lint/golint \
 && go get -u -v github.com/Masterminds/glide

WORKDIR /go/src/github.com/akatrevorjay/dnsdock

COPY glide.* ./
RUN glide i

COPY main.go ./
COPY core utils servers ./

RUN go install .

CMD ["dnsdock"]
