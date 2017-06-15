package servers

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/akatrevorjay/doxy/utils"
)

// ServiceMux stores service state and muxes events to ServiceHandler's
type ServiceMux struct {
	sync.RWMutex
	config   *utils.Config
	services map[string]*Service
	handlers map[string]*ServiceHandler
	domains  map[string]*Service
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

	if query == "" {
		logger.Warningf("Got empty query?")
		return c
	}

	// trim off any trailing dot
	if query[len(query)-1] == '.' {
		query = query[:len(query)-1]
	}

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
