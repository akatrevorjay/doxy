package utils

import (
	"fmt"
	"os"
	"path"
	"strings"
	//"github.com/spf13/viper"
)

// Domain represents a domain
type Domain []string

// NewDomain creates a new domain
func NewDomain(s string) Domain {
	s = strings.Replace(s, "..", ".", -1)
	if s[:1] == "." {
		s = s[1:]
	}
	if s[len(s)-1:] == "." {
		s = s[:len(s)-1]
	}
	return Domain(strings.Split(s, "."))
}

func (d *Domain) String() string {
	return strings.Join([]string(*d), ".")
}

// type that knows how to parse CSV strings and store the values in a slice
type nameservers []string

func (n *nameservers) String() string {
	return strings.Join(*n, " ")
}

// accumulate the CSV string of nameservers
func (n *nameservers) Set(value string) error {
	*n = nil
	for _, ns := range strings.Split(value, ",") {
		ns = strings.Trim(ns, " ")
		*n = append(*n, ns)
	}

	return nil
}

// Config contains configuration
type Config struct {
	Name            string

	DnsEnable		bool
	DnsAddr         string
	Domain          Domain

	Nameservers     nameservers
	ProxyDNS		bool
	ProxyNameserversFromResolvconf bool

	// docker
	DockerHost      string
	DockerTlsVerify bool
	DockerTlsCaCert string
	DockerTlsCert   string
	DockerTlsKey    string

	// http
	HttpEnable		bool
	HttpAddr        string
	HttpsAddr       string

	// socks
	SocksEnable		bool
	SocksAddr       string

	// tls
	TlsGenRsaBits   int
	TlsCaKey        string
	TlsCert         string
	// misc
	Ttl             int
	ForceTtl        bool
	CreateAlias     bool
	// logging
	Verbose         bool
	Quiet           bool
	All             bool
}

func (c *Config) GetEnvPrefix() string {
	return fmt.Sprintf("%s_", strings.ToUpper(c.Name))
}

func (c *Config) GetLabelPrefix() string {
	return fmt.Sprintf("%s.", strings.ToLower(c.Name))
}

// NewConfig creates a new config
func NewConfig() *Config {
	dockerHost := os.Getenv("DOCKER_HOST")
	if len(dockerHost) == 0 {
		dockerHost = "unix:///var/run/docker.sock"
	}

	dockerTlsVerify := len(os.Getenv("DOCKER_TLS_VERIFY")) != 0

	dockerCerts := os.Getenv("DOCKER_CERT_PATH")
	if len(dockerCerts) == 0 {
		dockerCerts = os.Getenv("HOME") + "/.docker"
	}

	caPath := os.Getenv("CA_PATH")
	if len(caPath) == 0 {
		caPath = "."
	}

	return &Config{
		Name:            "doxy",
		Nameservers:     nameservers{},

		SocksEnable:	 false,
		HttpEnable:		 true,
		DnsEnable:		 true,

		ProxyDNS:		 false,
		ProxyNameserversFromResolvconf: true,

		DnsAddr:         ":8053",
		Domain:          NewDomain("docker"),
		DockerHost:      dockerHost,
		HttpAddr:        ":8080",
		HttpsAddr:       ":8443",
		SocksAddr:		 ":1080",
		CreateAlias:     true,
		DockerTlsVerify: dockerTlsVerify,
		DockerTlsCaCert: dockerCerts + "/ca.pem",
		DockerTlsCert:   dockerCerts + "/cert.pem",
		DockerTlsKey:    dockerCerts + "/key.pem",
		TlsCaKey:        path.Join(caPath, "ca.key"),
		TlsCert:         path.Join(caPath, "cert.pem"),
		TlsGenRsaBits:   4096,
		Verbose:         true,
		Quiet:           false,
		All:             false,
		ForceTtl:        false,
		Ttl:             0,
	}
}

