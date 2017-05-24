/* doxy.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"sync"

	"github.com/op/go-logging"

	"github.com/akatrevorjay/doxy/core"
	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"
)

// GitSummary contains the version number
var GitSummary string
var logger = logging.MustGetLogger("doxy.main")

func orPanic(err error) {
	if err != nil {
		logger.Fatalf("Error: %s", err.Error())
	}
}

func main() {
	var cmdLine = core.NewCommandLine(GitSummary)

	config, err := cmdLine.ParseParameters(os.Args[1:])
	orPanic(err)

	verbosity := 0
	if config.Quiet == false {
		if config.Verbose == false {
			verbosity = 1
		} else {
			verbosity = 2
		}
	}

	err = utils.InitLoggers(verbosity)
	orPanic(err)

	logger.Infof("Init")

	var tlsConfig *tls.Config
	if config.DockerTlsVerify {
		clientCert, err := tls.LoadX509KeyPair(config.DockerTlsCert, config.DockerTlsKey)
		orPanic(err)

		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{clientCert},
		}

		pemData, err := ioutil.ReadFile(config.DockerTlsCaCert)
		orPanic(err)

		rootCert := x509.NewCertPool()
		rootCert.AppendCertsFromPEM(pemData)
		tlsConfig.RootCAs = rootCert
	}

	list, err := servers.NewServiceMux(config)
	orPanic(err)

	dnsServer, err := servers.NewDNSServer(config, list)
	orPanic(err)
	list.RegisterHandler("dns", dnsServer)

	httpProxyServer, err := servers.NewHTTPProxyServer(config, list)
	orPanic(err)
	list.RegisterHandler("http", httpProxyServer)

	docker, err := core.NewDockerManager(config, list, tlsConfig)
	orPanic(err)

	err = dnsServer.Start()
	orPanic(err)

	err = httpProxyServer.Start()
	orPanic(err)

	err = docker.Start()
	orPanic(err)

	err = docker.AddExisting()
	orPanic(err)

	logger.Infof("Ready.")

	// Wait forever
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
