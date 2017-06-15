package socks

import (
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("doxy.servers.socks")

func orPanic(err error) {
	if err == nil {
		return
	}
	panic(err)
}

func orFatalf(err error) {
	if err == nil {
		return
	}
	logger.Fatalf("Error: %s", err.Error())
}

func orErrorf(err error) {
	if err == nil {
		return
	}
	logger.Errorf("Error: %s", err.Error())
}
