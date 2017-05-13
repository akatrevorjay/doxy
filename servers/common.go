package servers

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/docker/go-connections/nat"
	"github.com/akatrevorjay/doxy/utils"
	"github.com/miekg/dns"
)

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

// Service represents a container and an attached DNS record
type Service struct {
	ID       string
	Name     string
	Image    string
	Primary  string
	Aliases  []string
	IPs      []net.IP
	TTL      int
	Ports    nat.PortMap
	HttpPort string
}

// NewService creates a new service
func NewService() (*Service, error) {
	s := &Service{TTL: -1}
	return s, nil
}

func (s Service) String() string {
	return fmt.Sprintf("Service{name=%s primary=%s aliases=%s ports=%s httpPort=%s ips=%s ttl=%d}", s.Name, s.Primary, s.Aliases, s.Ports, s.HttpPort, s.IPs, s.TTL)
}

// ListDomains lists domains
func (service *Service) ListDomains(suffix string, end bool) chan string {
	gen := func() chan string {
		out := make(chan string)
		go func() {
			// Service name
			out <- service.Name

			// Set aliases for this service (ie from labels)
			for _, alias := range service.Aliases {
				out <- alias
			}

			close(out)
		}()
		return out
	}

	// Primordial goo
	c := gen()

	if service.Image != "" {
		// If we happen to know our image, add as suffix
		c = utils.ChanSuffix(c, utils.DomainJoin("", service.Image), true)
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

func (s *Service) HasPrefixMatch(query string, suffix string) (string, error) {
	squery := dns.SplitDomainName(query)

	for domain := range s.ListDomains(suffix, false) {
		sdomain := dns.SplitDomainName(domain)
		if isPrefixQuery(squery, sdomain) {
			return domain, nil
		}
	}

	return "", nil
}

type ServiceHandler interface {
	AddService(string, *Service) error
	RemoveService(string) error
}

// ServiceListProvider represents the entrypoint to get containers
type ServiceListProvider interface {
	ServiceHandler
	GetService(string) (*Service, error)
	GetAllServices() (map[string]*Service, error)
	QueryServices(string) chan *Service
	QueryServicesByIP(net.IP) chan *Service
}

// ServiceMux stores service state and muxes events to ServiceHandler's
type ServiceMux struct {
	sync.RWMutex
	config   *utils.Config
	services map[string]*Service
	handlers map[string]*ServiceHandler
}

// NewServiceMux creates a new ServiceMux
func NewServiceMux(c *utils.Config) (*ServiceMux, error) {
	s := &ServiceMux{
		config:   c,
		services: make(map[string]*Service),
		handlers: make(map[string]*ServiceHandler),
	}

	return s, nil
}

// Checks for a partial match for container SHA and outputs it if found.
func (s *ServiceMux) getExpandedID(in string) (out string) {
	out = in

	// Hard to make a judgement on small image names.
	if len(in) < 4 {
		return
	}

	if isHex, _ := regexp.MatchString("^[0-9a-f]+$", in); !isHex {
		return
	}

	for id := range s.services {
		if len(id) != 64 {
			continue
		}

		if isHex, _ := regexp.MatchString("^[0-9a-f]+$", id); isHex {
			if strings.HasPrefix(id, in) {
				out = id
				return
			}
		}
	}
	return
}

// GetService reads a service from the repository
func (s *ServiceMux) GetService(id string) (*Service, error) {
	id = s.getExpandedID(id)

	if s, ok := s.services[id]; ok {
		return s, nil
	}

	// Check for a pa
	return new(Service), errors.New("No such service: " + id)
}

// GetAllServices reads all services from the repository
func (s *ServiceMux) GetAllServices() (map[string]*Service, error) {
	list := make(map[string]*Service, len(s.services))
	for id, service := range s.services {
		list[id] = service
	}

	return list, nil
}

// QueryServices queries services
func (s *ServiceMux) QueryServices(query string) chan *Service {
	c := make(chan *Service, 3)

	go func() {
		suffix := s.config.Domain.String()

		services, err := s.GetAllServices()
		orPanic(err)

		for _, service := range services {
			domain, err := service.HasPrefixMatch(query, suffix)
			orPanic(err)

			if domain != "" {
				c <- service
			}
		}

		close(c)
	}()

	return c
}

// QueryServicesByIP Queries services by IP
func (s *ServiceMux) QueryServicesByIP(ip net.IP) chan *Service {
	c := make(chan *Service, 3)
	ipstr := ip.String()

	go func() {
		services, err := s.GetAllServices()
		orPanic(err)

		for _, service := range services {
			for _, sip := range service.IPs {
				if sip.String() != ipstr {
					break
				}

				c <- service
			}
		}

		close(c)
	}()

	return c
}

// RegisterHandler registers a handler
func (s *ServiceMux) RegisterHandler(name string, handler ServiceHandler) error {
	s.Lock()
	s.handlers[name] = &handler
	s.Unlock()

	return nil
}

// AddService adds a new service
func (s *ServiceMux) AddService(id string, service *Service) error {
	id = s.getExpandedID(id)
	service.ID = id

	logger.Debugf("Adding service=%s id=%s", service.Name, id)

	s.Lock()
	s.services[id] = service
	s.Unlock()

	for _, handler := range s.handlers {
		(*handler).AddService(id, service)
	}

	logger.Infof("Added service id=%s name=%s", id, service.Name)

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *ServiceMux) RemoveService(id string) error {
	id = s.getExpandedID(id)

	service, err := s.GetService(id)
	if err != nil {
		logger.Errorf("Cannot remove a service that doesn't already exist. id=%s", id)
		return nil
	}

	logger.Debugf("Removing service id=%s name=%s", id, service.Name)

	for _, handler := range s.handlers {
		(*handler).RemoveService(id)
	}

	s.Lock()
	delete(s.services, id)
	s.Unlock()

	logger.Infof("Removed service id=%s name=%s", id, service.Name)

	return nil
}
