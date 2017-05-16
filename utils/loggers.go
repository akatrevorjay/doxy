/* loggers.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package utils

import (
	"github.com/op/go-logging"
	"os"
)

// InitLoggers initialize loggers
func InitLoggers(verbosity int) (err error) {
	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{module} %{longfunc} %{color:bold}%{message} %{color:reset}%{color}@%{shortfile} %{color}#%{level}%{color:reset}`,
	)

	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	//logging.SetBackend(formatter)

	leveledBackend := logging.AddModuleLevel(formatter)

	switch {
	case verbosity == 1:
		logging.SetLevel(logging.INFO, "")
		leveledBackend.SetLevel(logging.INFO, "")
	case verbosity >= 2:
		logging.SetLevel(logging.DEBUG, "")
		leveledBackend.SetLevel(logging.DEBUG, "")
	}

	logging.SetBackend(leveledBackend)
	return
}
