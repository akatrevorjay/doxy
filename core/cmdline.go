/* cmdline.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package core

import (
	"fmt"
	"strconv"

	"github.com/akatrevorjay/doxy/utils"
	"gopkg.in/alecthomas/kingpin.v2"
)

// CommandLine structure handling parameter parsing
type CommandLine struct {
	app *kingpin.Application
}

func NewCommandLine(version string) (res *CommandLine) {
	res = &CommandLine{}
	res.app = kingpin.New("doxy", "Automatic DNS for docker containers.")
	res.app.Version(version)
	res.app.HelpFlag.Short('h')
	return
}

// ParseParameters Parse parameters
func (cmdline *CommandLine) ParseParameters(rawParams []string) (res *utils.Config, err error) {
	res = utils.NewConfig()

	name := cmdline.app.Flag("name", "Name of this host. used for SOA").Default(res.Name).Short('n').String()
	verbose := cmdline.app.Flag("verbose", "Verbose mode.").Default(strconv.FormatBool(res.Verbose)).Short('v').Bool()
	quiet := cmdline.app.Flag("quiet", "Quiet mode.").Default(strconv.FormatBool(res.Quiet)).Short('q').Bool()

	http := cmdline.app.Flag("http", "Listen HTTP requests on this address").Default(res.HttpAddr).Short('H').String()
	https := cmdline.app.Flag("https", "Listen HTTPS requests on this address").Default(res.HttpsAddr).Short('I').String()
	dns := cmdline.app.Flag("dns", "Listen DNS requests on this address").Default(res.DnsAddr).Short('D').String()

	domain := cmdline.app.Flag("domain", "Domain that is appended to all requests").Default(res.Domain.String()).String()
	environment := cmdline.app.Flag("environment", "Optional context before domain suffix").Default("").String()
	createAlias := cmdline.app.Flag("alias", "Automatically create an alias with just the container name.").Default(strconv.FormatBool(res.CreateAlias)).Bool()
	all := cmdline.app.Flag("all", "Process all containers even if they are stopped.").Default(strconv.FormatBool(res.All)).Short('a').Bool()

	nameservers := cmdline.app.Flag("nameserver", "Comma separated list of DNS server(s) for unmatched requests").Strings()
	ttl := cmdline.app.Flag("ttl", "TTL for matched requests").Default(strconv.FormatInt(int64(res.Ttl), 10)).Int()
	forceTtl := cmdline.app.Flag("forcettl", "Force TTL value even for forwared requests.").Bool()

	docker := cmdline.app.Flag("docker", "Path to the docker socket").Default(res.DockerHost).String()
	tlsverify := cmdline.app.Flag("tlsverify", "Enable mTLS when connecting to docker").Default(strconv.FormatBool(res.TlsVerify)).Bool()
	tlscacert := cmdline.app.Flag("tlscacert", "Path to CA certificate").Default(res.TlsCaCert).String()
	tlscert := cmdline.app.Flag("tlscert", "Path to Client certificate").Default(res.TlsCert).String()
	tlskey := cmdline.app.Flag("tlskey", "Path to client certificate private key").Default(res.TlsKey).String()

	kingpin.MustParse(cmdline.app.Parse(rawParams))

	res.Name = *name
	res.Verbose = *verbose
	res.Quiet = *quiet
	res.Nameservers = *nameservers
	res.DnsAddr = *dns
	res.HttpAddr = *http
	res.HttpsAddr = *https
	res.Domain = utils.NewDomain(fmt.Sprintf("%s.%s", *environment, *domain))
	res.DockerHost = *docker
	res.TlsVerify = *tlsverify
	res.TlsCaCert = *tlscacert
	res.TlsCert = *tlscert
	res.TlsKey = *tlskey
	res.Ttl = *ttl
	res.CreateAlias = *createAlias
	res.All = *all
	res.ForceTtl = *forceTtl
	return
}
