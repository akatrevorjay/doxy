package socks

import (
	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"

	"github.com/cybozu-go/usocksd/socks"
)

// Listeners returns a list of net.Listener.
func Listeners(c *Config) ([]net.Listener, error) {
	if len(c.Incoming.Addresses) == 0 {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(c.Incoming.Port))
		if err != nil {
			return nil, err
		}
		return []net.Listener{ln}, nil
	}

	lns := make([]net.Listener, len(c.Incoming.Addresses))
	for i, a := range c.Incoming.Addresses {
		addr := net.JoinHostPort(a.String(), strconv.Itoa(c.Incoming.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for j := 0; j < i; j++ {
				lns[j].Close()
			}
			return nil, err
		}
		lns[i] = ln
	}
	return lns, nil
}

// NewServer creates a new socks.Server.
func NewServer() *socks.Server {
	return &socks.Server{
		//Rules:  createRuleSet(c),
		//Dialer: createDialer(c),
	}
}

// ProxyHTTPServer represents the proxy endpoint
type SocksServer struct {
	config *utils.Config
	list   *ServiceListProvider
	server *usocksd.SocksServer
	mux *vhost.HTTPMuxer
}

func NewHTTPProxyServer(c *utils.Config, list ServiceListProvider) (*SocksServer, error) {
	s := &SocksServer{
		config: c,
		list:   &list,
	}

	server := NewServer()

	s.server = proxy
	return s, nil
}

// Start starts the socks endpoints
func (s *SocksServer) Start() error {
	logger.Infof("Starting SocksServer; listening on socks=%s sockss=%s.", s.config.SocksAddr, s.config.SocksTlsAddr)

	lns := make([]net.Listener, len(c.Incoming.Addresses))
	for i, a := range c.Incoming.Addresses {
		addr := net.JoinHostPort(a.String(), strconv.Itoa(c.Incoming.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for j := 0; j < i; j++ {
				lns[j].Close()
			}
			return nil, err
		}
		lns[i] = ln
	}
	return lns, nil

	return nil
}

// AddService adds a new container and thus new DNS records
func (s *SocksServer) AddService(id string, service *Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", service.Name)
		return nil
	}

	added := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		//s.AddProxyDomain(domain)

		//ml, _ := s.mux.Listen(domain)

		//go func(vh virtualHost, ml net.Listener) {
		//    for {
		//        conn, _ := ml.Accept()
		//        go vh.Handle(conn)
		//    }
		//}(vhost, ml)

		added = append(added, domain)
	}
	logger.Infof("Handling HTTP zones for service=%s: %v", service.Name, added)

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *SocksServer) RemoveService(id string) error {
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
		//s.RemoveProxyDomain(domain)

		removed = append(removed, domain)
	}
	logger.Infof("Removed HTTP zones for service=%s: %v", service.Name, removed)

	return nil
}
