package servers

import (
	"fmt"
	"net"
)

// Service represents a container and an attached DNS record
type Service struct {
	Name    string
	Image   string
	IPs     []net.IP
	TTL     int
	Primary string
	Aliases []string
}

// NewService creates a new service
func NewService() (s *Service) {
	s = &Service{TTL: -1}
	return
}

func (s Service) String() string {
	return fmt.Sprintf(` Name:    %s
                       Primary: %s
                       Aliases: %s
                       IPs:     %s
                       TTL:     %d
        `, s.Name, s.Primary, s.Aliases, s.IPs, s.TTL)
}

// ServiceListProvider represents the entrypoint to get containers
type ServiceListProvider interface {
	AddService(string, Service) error
	RemoveService(string) error
	GetService(string) (Service, error)
	GetAllServices() map[string]Service
	QueryServices(string) chan *Service
}

