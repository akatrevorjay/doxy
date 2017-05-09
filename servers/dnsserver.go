/* dnsserver.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package servers

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/akatrevorjay/doxyroxy/utils"
	"github.com/miekg/dns"
	"github.com/olebedev/emitter"
)

type ServiceList struct {
	config *utils.Config
}

// DNSServer represents a DNS server
type DNSServer struct {
	config   *utils.Config
	server   *dns.Server
	mux      *dns.ServeMux
	services map[string]*Service
	lock     *sync.RWMutex
	events   *emitter.Emitter
}

// NewDNSServer create a new DNSServer
func NewDNSServer(c *utils.Config, events *emitter.Emitter) *DNSServer {
	s := &DNSServer{
		config:   c,
		services: make(map[string]*Service),
		lock:     &sync.RWMutex{},
		events:	  events,
	}

	logger.Debugf("Handling DNS requests for '%s'.", c.Domain.String())

	s.mux = dns.NewServeMux()
	s.mux.HandleFunc(c.Domain.String()+".", s.handleRequest)
	s.mux.HandleFunc("in-addr.arpa.", s.handleReverseRequest)
	s.mux.HandleFunc(".", s.handleForward)

	s.server = &dns.Server{Addr: c.DnsAddr, Net: "udp", Handler: s.mux}

	return s
}

// Start starts the DNSServer
func (s *DNSServer) Start() error {
	return s.server.ListenAndServe()
}

// Stop stops the DNSServer
func (s *DNSServer) Stop() {
	s.server.Shutdown()
}

func (s *DNSServer) getServicePrimary(svc Service) string {
	return utils.DomainJoin(svc.Name, s.config.Domain.String(), "")
}

// AddService adds a new container and thus new DNS records
func (s *DNSServer) AddService(id string, service Service) {
	if len(service.Primary) == 0 {
		service.Primary = s.getServicePrimary(service)
	}

	if len(service.IPs) > 0 {
		defer s.lock.Unlock()
		s.lock.Lock()

		id = s.getExpandedID(id)
		s.services[id] = &service

		logger.Debugf(`Added service: '%s'
                      %s`, id, service)
		<-s.events.Emit("service:added", id)
		<-s.events.Emit("service:domain:primary", id, service.Primary)

		for domain := range service.ListDomains(s.config.Domain.String(), true) {
			logger.Debugf("Handling DNS requests for domain='%s'.", domain)
			s.mux.HandleFunc(domain, s.handleRequest)
			<-s.events.Emit("service:domain:added", id, domain)
		}
	} else {
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
	}
}

// RemoveService removes a new container and thus DNS records
func (s *DNSServer) RemoveService(id string) error {
	defer s.lock.Unlock()
	s.lock.Lock()

	id = s.getExpandedID(id)
	if _, ok := s.services[id]; !ok {
		return errors.New("No such service: " + id)
	}

	for domain := range s.services[id].ListDomains(s.config.Domain.String(), true) {
		s.mux.HandleRemove(domain)
		<-s.events.Emit("service:domain:removed", id, domain)
	}

	delete(s.services, id)

	logger.Debugf("Removed service '%s'", id)
	<-s.events.Emit("service:removed", id)

	return nil
}

// GetService reads a service from the repository
func (s *DNSServer) GetService(id string) (Service, error) {
	defer s.lock.RUnlock()
	s.lock.RLock()

	id = s.getExpandedID(id)
	if s, ok := s.services[id]; ok {
		return *s, nil
	}
	// Check for a pa
	return *new(Service), errors.New("No such service: " + id)
}

// GetAllServices reads all services from the repository
func (s *DNSServer) GetAllServices() map[string]Service {
	defer s.lock.RUnlock()
	s.lock.RLock()

	list := make(map[string]Service, len(s.services))
	for id, service := range s.services {
		list[id] = *service
	}

	return list
}

// ChanSuffix Suffixes all items in a string channel with a given suffix
func ChanSuffix(in chan string, suffix string, orig bool) chan string {
	out := make(chan string)
	go func() {
		for domain := range in {
			if domain == "" {
				continue
			}

			//logger.Debugf("aliasing domain=%s with suffix=%s", domain, suffix)
			out <- domain + suffix
			if orig {
				out <- domain
			}
		}
		close(out)
	}()
	return out
}

func (service *Service) ListDomains(suffix string, end bool) chan string {
	logger.Debugf("Service name=%s", service.Name)

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
		c = ChanSuffix(c, utils.DomainJoin("", service.Image), true)
	}

	// Domain suffix
	if suffix != "" {
		c = ChanSuffix(c, utils.DomainJoin("", suffix), true)
	}

	if end {
		// All must end with a period.
		c = ChanSuffix(c, ".", false)
	}

	return c
}

func (s *DNSServer) handleForward(w dns.ResponseWriter, r *dns.Msg) {

	logger.Debugf("Using DNS forwarding for '%s'", r.Question[0].Name)
	logger.Debugf("Forwarding DNS nameservers: %s", s.config.Nameservers.String())

	// Otherwise just forward the request to another server
	c := new(dns.Client)

	// look at each Nameserver, stop on success
	for i := range s.config.Nameservers {
		logger.Debugf("Using Nameserver %s", s.config.Nameservers[i])

		in, _, err := c.Exchange(r, s.config.Nameservers[i])
		if err == nil {
			if s.config.ForceTtl {
				logger.Debugf("Forcing Ttl value of the forwarded response")
				for _, rr := range in.Answer {
					rr.Header().Ttl = uint32(s.config.Ttl)
				}
			}
			w.WriteMsg(in)
			return
		}

		if i == (len(s.config.Nameservers) - 1) {
			logger.Warningf("DNS fowarding failed: no more nameservers to try")

			// Send failure reply
			m := new(dns.Msg)
			m.SetReply(r)
			m.Ns = s.createSOA()
			m.SetRcode(r, dns.RcodeRefused) // REFUSED
			w.WriteMsg(m)

		} else {
			logger.Debugf("DNS fowarding failed: trying next Nameserver...")
		}
	}
}

func (s *DNSServer) makeServiceA(n string, service *Service) dns.RR {
	var ttl int
	if service.TTL != -1 {
		ttl = service.TTL
	} else {
		ttl = s.config.Ttl
	}

	rr := new(dns.A)

	rr.Hdr = dns.RR_Header{
		Name:   n,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    uint32(ttl),
	}

	if len(service.IPs) != 0 {
		if len(service.IPs) > 1 {
			logger.Warningf("Multiple IP address found for container '%s'. Only the first address will be used", service.Name)
		}
		rr.A = service.IPs[0]
	} else {
		logger.Errorf("No valid IP address found for container '%s' ", service.Name)
	}

	return rr
}

func (s *DNSServer) makeServiceMX(n string, service *Service) dns.RR {
	rr := new(dns.MX)

	var ttl int
	if service.TTL != -1 {
		ttl = service.TTL
	} else {
		ttl = s.config.Ttl
	}

	rr.Hdr = dns.RR_Header{
		Name:   n,
		Rrtype: dns.TypeMX,
		Class:  dns.ClassINET,
		Ttl:    uint32(ttl),
	}

	rr.Mx = n

	return rr
}

func (s *DNSServer) makeServiceCNAME(n string, service *Service) dns.RR {
	rr := new(dns.CNAME)

	var ttl int
	if service.TTL != -1 {
		ttl = service.TTL
	} else {
		ttl = s.config.Ttl
	}

	rr.Hdr = dns.RR_Header{
		Name:   n,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    uint32(ttl),
	}

	rr.Target = service.Primary

	return rr
}

func (s *DNSServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

	// Send empty response for empty requests
	if len(r.Question) == 0 {
		m.Ns = s.createSOA()
		w.WriteMsg(m)
		return
	}

	// respond to SOA requests
	if r.Question[0].Qtype == dns.TypeSOA {
		m.Answer = s.createSOA()
		w.WriteMsg(m)
		return
	}

	m.Answer = make([]dns.RR, 0, 2)
	query := r.Question[0].Name

	// trim off any trailing dot
	if query[len(query)-1] == '.' {
		query = query[:len(query)-1]
	}

	logger.Debugf("DNS request for query '%s' from remote '%s'", query, w.RemoteAddr())

	for service := range s.queryServices(query) {
		var rr dns.RR
		switch r.Question[0].Qtype {
		case dns.TypeA:
			if r.Question[0].Name != service.Primary {
				rr = s.makeServiceCNAME(r.Question[0].Name, service)
				m.Answer = append(m.Answer, rr)
			}
			rr = s.makeServiceA(service.Primary, service)
		case dns.TypeMX:
			rr = s.makeServiceMX(r.Question[0].Name, service)
		default:
			// this query type isn't supported, but we do have
			// a record with this name. Per RFC 4074 sec. 3, we
			// immediately return an empty NOERROR reply.
			m.Ns = s.createSOA()
			m.MsgHdr.Authoritative = true
			w.WriteMsg(m)
			return
		}

		logger.Debugf("DNS record found for query '%s'", query)

		m.Answer = append(m.Answer, rr)
	}

	// We didn't find a record corresponding to the query
	if len(m.Answer) == 0 {
		m.Ns = s.createSOA()
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		logger.Debugf("No DNS record found for query '%s'", query)
	}

	w.WriteMsg(m)
}

func (s *DNSServer) handleReverseRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

	// Send empty response for empty requests
	if len(r.Question) == 0 {
		m.Ns = s.createSOA()
		w.WriteMsg(m)
		return
	}

	m.Answer = make([]dns.RR, 0, 2)

	// trim off any trailing dot
	query := r.Question[0].Name
	if query[len(query)-1] == '.' {
		query = query[:len(query)-1]
	}

	for service := range s.queryIP(query) {
		if r.Question[0].Qtype != dns.TypePTR {
			m.Ns = s.createSOA()
			w.WriteMsg(m)
			return
		}

		var ttl int
		if service.TTL != -1 {
			ttl = service.TTL
		} else {
			ttl = s.config.Ttl
		}

		for domain := range service.ListDomains(s.config.Domain.String(), true) {
			rr := new(dns.PTR)
			rr.Hdr = dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl),
			}
			rr.Ptr = domain

			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) != 0 {
		w.WriteMsg(m)
	} else {
		// We didn't find a record corresponding to the query,
		// try forwarding
		s.handleForward(w, r)
	}
}

func (s *DNSServer) queryIP(query string) chan *Service {
	c := make(chan *Service, 3)
	reversedIP := strings.TrimSuffix(query, ".in-addr.arpa")
	ip := strings.Join(utils.Reverse(strings.Split(reversedIP, ".")), ".")

	go func() {
		defer s.lock.RUnlock()
		s.lock.RLock()

		for _, service := range s.services {
			if service.IPs[0].String() == ip {
				c <- service
			}
		}

		close(c)
	}()

	return c
}

func (s *Service) hasPrefixMatch(query string, suffix string) string {
	utils.Dump(query)
	squery := utils.DomainSplit(query)

	for domain := range s.ListDomains(suffix, false) {
		utils.Dump(domain)

		sdomain := utils.DomainSplit(domain)
		if isPrefixQuery(squery, sdomain) {
			return domain
		}
	}
	return ""
}

func (s *DNSServer) queryServices(query string) chan *Service {
	c := make(chan *Service, 3)

	go func() {
		suffix := s.config.Domain.String()

		defer s.lock.RUnlock()
		s.lock.RLock()

		for _, service := range s.services {
			if domain := service.hasPrefixMatch(query, suffix); domain != "" {
				c <- service
			}
		}

		close(c)
	}()

	return c
}

// Checks for a partial match for container SHA and outputs it if found.
func (s *DNSServer) getExpandedID(in string) (out string) {
	out = in

	// Hard to make a judgement on small image names.
	if len(in) < 4 {
		return
	}

	if isHex, _ := regexp.MatchString("^[0-9a-f]+$", in); !isHex {
		return
	}

	for id := range s.services {
		if len(id) == 64 {
			if isHex, _ := regexp.MatchString("^[0-9a-f]+$", id); isHex {
				if strings.HasPrefix(id, in) {
					out = id
					return
				}
			}
		}
	}
	return
}

// TTL is used from config so that not-found result responses are not cached
// for a long time. The other defaults left as is(skydns source) because they
// do not have an use case in this situation.
func (s *DNSServer) createSOA() []dns.RR {
	dom := s.config.Domain.String()
	name := s.config.Name
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dom,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    uint32(s.config.Ttl),
		},
		Ns:      utils.DomainJoin(name, dom, ""),
		Mbox:    utils.DomainJoin(name, name, dom, ""),
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  uint32(s.config.Ttl),
	}
	return []dns.RR{soa}
}

// isPrefixQuery is used to determine whether "query" is a potential prefix
// query for "name". It allows for wildcards (*) in the query. However is makes
// one exception to accomodate the desired behavior we wish from doxyroxy,
// namely, the query may be longer than "name" and still be a valid prefix
// query for "name".
// Examples:
//   foo.bar.baz.qux is a valid query for bar.baz.qux (longer prefix is okay)
//   foo.*.baz.qux   is a valid query for bar.baz.qux (wildcards okay)
//   *.baz.qux       is a valid query for baz.baz.qux (wildcard prefix okay)
func isPrefixQuery(query, name []string) bool {
	for i, j := len(query)-1, len(name)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if query[i] != name[j] && query[i] != "*" {
			return false
		}
	}
	return true
}
