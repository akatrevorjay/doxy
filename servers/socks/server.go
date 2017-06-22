package socks

import (
	"net"
	"strconv"
	"time"
	"fmt"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"

	"github.com/docker/go-connections/nat"

	"github.com/cybozu-go/usocksd/socks"
	//"github.com/cybozu-go/usocksd"
)

type dumbDialer struct {
	*net.Dialer
}

func (d dumbDialer) Dial(r *socks.Request) (net.Conn, error) {
	var addr string
	if len(r.Hostname) > 0 {
		addr = net.JoinHostPort(r.Hostname, strconv.Itoa(r.Port))
	} else {
		addr = net.JoinHostPort(r.IP.String(), strconv.Itoa(r.Port))
	}
	return d.DialContext(r.Context(), "tcp", addr)
}

type adaptedDialer struct {
	*net.Dialer
	adaptDestinationRequest func(*socks.Request)
}

func (d adaptedDialer) Dial(r *socks.Request) (net.Conn, error) {
	d.adaptDestinationRequest(r)

	var host string = r.Hostname
	var port int = r.Port

	// Use IP if we didn't get a name for some reason
	if host == "" {
		host = r.IP.String()
	}

	var addr string = net.JoinHostPort(host, strconv.Itoa(port))

	return d.DialContext(r.Context(), "tcp", addr)
}

func (s *SocksProxy) adaptDestinationRequest(r *socks.Request) {
	var host string = r.Hostname
	var port int = r.Port

	// Use IP if we didn't get a name for some reason
	if host == "" {
		host = r.IP.String()
	}

	var origScheme string = "socks"
	var origAddr string = net.JoinHostPort(host, strconv.Itoa(port))

	newAddr, _, err := s.adaptDestination(origAddr, origScheme)
	if err != nil {
		err := fmt.Errorf("Failed to adapt destination %s://%s: %v", origScheme, origAddr, err)
		panic(err)
	}

	newHost, newPortstr, err := net.SplitHostPort(newAddr)
	orPanic(err)
	newPort, err := strconv.Atoi(newPortstr)
	orPanic(err)

	//logger.Debugf("New connection %v => %s://%s", conn.RemoteAddr(), scheme, addr)

	r.Hostname = newHost
	r.Port = newPort
}

// TODO Look up from DNS
func (s *SocksProxy) adaptDestination(addr string, scheme string) (newAddr string, newScheme string, err error) {
	var port int

	newAddr, newScheme = addr, scheme

	host, rawPort, err := net.SplitHostPort(addr)
	if err == nil {
		port, _ = nat.ParsePort(rawPort)
	} else {
		host = addr
	}

	if port == 0 {
		switch scheme {
		case "https":
			port = 443
			break
		default:
			port = 80
			break
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		logger.Warningf("Not adapting IP: %s", ip)
	} else {
		var svc *servers.Service
		for svc = range (*s.list).QueryServices(host) {
			break
		}

		if svc == nil {
			err = fmt.Errorf("Service not available by name: %v", addr)
			return newAddr, newScheme, err
		}

		if len(svc.IPs) < 1 {
			err = fmt.Errorf("Service does not have an IP: %v", svc)
			return newAddr, newScheme, err
		}
		ip = svc.IPs[0]

		if svc.HttpPort != 0 {
			newScheme = "http"
			port = svc.HttpPort
		}

		if svc.HttpsPreferred && svc.HttpsPort != 0 {
			newScheme = "https"
			port = svc.HttpsPort
		}

		if port == 0 || newScheme == "" {
			err = fmt.Errorf("Service matched, but no ports matched requested scheme=%s service=%s", scheme, svc)
			return newAddr, newScheme, err
		}

		newAddr = net.JoinHostPort(ip.String(), strconv.FormatInt(int64(port), 10))

		logger.Debugf("Adapted request dest: %s://%s => %s://%s", scheme, addr, newScheme, newAddr)
	}

	return newAddr, newScheme, nil

}

// ProxySocksServer represents the proxy endpoint
type SocksProxy struct {
	config *utils.Config
	list   *servers.ServiceListProvider
	server *socks.Server
	ln     *net.Listener
}

func NewSocksProxy(c *utils.Config, list servers.ServiceListProvider) (*SocksProxy, error) {
	s := &SocksProxy{
		config: c,
		list:   &list,
	}

	dialer := adaptedDialer{
		adaptDestinationRequest: s.adaptDestinationRequest,
		Dialer: &net.Dialer{
			KeepAlive: 3 * time.Minute,
			DualStack: true,
		},
	}

	server := &socks.Server{
		//Rules:  usocksd.createRuleSet(c),
		Dialer: &dialer,
	}

	s.server = server

	return s, nil
}

// Start starts the socks endpoints
func (s *SocksProxy) Start() error {
	logger.Infof("Starting SocksProxy; listening on socks=%s.", s.config.SocksAddr)

	ln, err := net.Listen("tcp", s.config.SocksAddr)
	if err != nil {
		panic(err)
	}

	go func(ln net.Listener) {
		s.server.Serve(ln)
	}(ln)

	return nil
}

// Stop stops the DnsServer
func (s *SocksProxy) Stop() {
	s.server.Env.Stop()
}

// AddService adds a new container and thus new DNS records
func (s *SocksProxy) AddService(id string, service *servers.Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", service.Name)
		return nil
	}

	added := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		// do something

		added = append(added, domain)
	}
	logger.Infof("Handling Socks zones for service=%s: %v", service.Name, added)

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *SocksProxy) RemoveService(id string) error {
	service, err := (*s.list).GetService(id)
	if err != nil {
		logger.Errorf("Cannot remove a service that doesn't already exist. id=%s", id)
		return nil
	}

	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", id, id)
		return nil
	}

	removed := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		// do something

		removed = append(removed, domain)
	}
	logger.Infof("Removed Socks zones for service=%s: %v", service.Name, removed)

	return nil
}
