package ca

import (
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("doxy.utils.ca")

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
