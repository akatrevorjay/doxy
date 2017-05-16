package servers

import (
	"net"
)

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
