package servers

import (
	//"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	//"sync"

	"github.com/akatrevorjay/doxy/utils"
	"github.com/docker/go-connections/nat"
	"github.com/miekg/dns"
)

// Service represents a container
type Service struct {
	ID    string
	Name  string
	Image string

	Ignore bool
	TTL    int

	Primary string
	Aliases []string

	IPs []net.IP
	Ports nat.PortMap

	HttpPort            string
	HttpsPort          string
	HttpsValidateCert  bool
	ForwardHttpsToHttp bool
	RedirectHttpToHttps bool
}

// NewService creates a new Service
func NewService() (*Service, error) {
	svc := &Service{
		Ignore: false,

		TTL: -1,

		RedirectHttpToHttps: false,
		HttpsValidateCert:   false,
		ForwardHttpsToHttp:  true,
	}

	return svc, nil
}

func (svc Service) String() string {
	return fmt.Sprintf(
		"Service{name=%s primary=%s aliases=%s ports=%s httpPort=%s ips=%s ttl=%d}",
		svc.Name, svc.Primary, svc.Aliases, svc.Ports, svc.HttpPort, svc.IPs, svc.TTL,
	)
}

// ApplyOverride applies a single possible override to the given Service.
func (svc *Service) ApplyOverride(k string, v string) error {
	mrclean, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return err
	}

	cleanedK := mrclean.ReplaceAllString(strings.ToLower(k), "")
	//logger.Debugf("Checking possible override: %s[%s]=%s for service_id=%s", k, cleanedK, v, svc.ID)

	switch cleanedK {
	case "ignore":
		bv, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		svc.Ignore = bv

	case "alias", "aliases":
		for _, alias := range strings.Split(v, ",") {
			if len(alias) == 0 {
				logger.Warningf("Got empty alias override for service=%v", svc.ID)
				continue
			}

			svc.Aliases = append(svc.Aliases, alias)
		}

	case "name":
		svc.Name = v

	case "primary", "hostname":
		svc.Primary = v

	case "image":
		svc.Image = v

	case "ttl":
		ttl, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		svc.TTL = ttl

	case "region":
		if len(v) > 0 {
			svc.Image = svc.Image + "." + v
		}

	case "ip", "ipaddr", "ipaddress":
		ipAddr := net.ParseIP(v)
		if ipAddr == nil {
			logger.Warningf("Got empty IP address override for service=%v", svc)
		} else {
			svc.IPs = svc.IPs[:0]
			svc.IPs = append(svc.IPs, ipAddr)
		}

	case "prefix":
		addrs := make([]net.IP, 0)
		for _, value := range svc.IPs {
			if strings.HasPrefix(value.String(), v) {
				addrs = append(addrs, value)
			}
		}
		if len(addrs) == 0 {
			logger.Warningf("The prefix '%s' didn't match any IP addresses of service '%s', the service will be ignored", v, svc.Name)
		}
		svc.IPs = addrs

	case "httpport":
		if _, err := strconv.Atoi(v); err != nil {
			return err
		}
		svc.HttpPort = v

	case "httpsport":
		if _, err := strconv.Atoi(v); err != nil {
			return err
		}
		svc.HttpsPort = v

	case "redirecthttptohttps":
		bv, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}

		svc.RedirectHttpToHttps = bv

	case "httpsvalidatecert":
		bv, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}

		svc.HttpsValidateCert = bv

	case "forwardhttpstohttp":
		bv, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}

		svc.ForwardHttpsToHttp = bv
	}
	return nil
}

// ApplyOverridesMapping applies mapping of possible overrides (with the given prefix) to the given Service.
func (svc *Service) ApplyOverridesMapping(mapping map[string]string, prefix string) {
	var name string
	for k, v := range mapping {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name = k[len(prefix):]

		svc.ApplyOverride(name, v)
	}
}

// ListDomains lists domains
func (svc *Service) ListDomains(suffix string, end bool) chan string {
	gen := func() chan string {
		out := make(chan string)
		go func() {
			// Service name
			out <- svc.Name

			// Set aliases for this svc (ie from labels)
			for _, alias := range svc.Aliases {
				out <- alias
			}

			close(out)
		}()
		return out
	}

	// Primordial goo
	c := gen()

	if svc.Image != "" {
		// If we happen to know our image, add as suffix
		c = utils.ChanSuffix(c, utils.DomainJoin("", svc.Image), true)
	}

	// Domain suffix
	if suffix != "" {
		c = utils.ChanSuffix(c, utils.DomainJoin("", suffix), true)
	}

	if end {
		// All must end with a period.
		c = utils.ChanSuffix(c, ".", false)
	}

	return c
}

func (svc *Service) HasPrefixMatch(query string, suffix string) (string, error) {
	squery := dns.SplitDomainName(query)

	for domain := range svc.ListDomains(suffix, false) {
		sdomain := dns.SplitDomainName(domain)
		if isPrefixQuery(squery, sdomain) {
			return domain, nil
		}
	}

	return "", nil
}
