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
	server_udp   *dns.Server
	server_tcp *dns.Server
	mux      *dns.ServeMux
	services map[string]*Service
	lock     *sync.RWMutex
	events   *emitter.Emitter
	client   *dns.Client
}

// NewDNSServer create a new DNSServer
func NewDNSServer(c *utils.Config, events *emitter.Emitter) (*DNSServer, error) {
	s := &DNSServer{
		config:   c,
		services: make(map[string]*Service),
		lock:     &sync.RWMutex{},
		events:   events,
		client:   &dns.Client{},
	}

	// Suppress multiple outstanding queries (with the same question, type and class)
	s.client.SingleInflight = true

	//s.clientLoadResolvconf()

	s.mux = dns.NewServeMux()

	s.mux.HandleFunc(c.Domain.String()+".", s.handleRequest)
	s.mux.HandleFunc("in-addr.arpa.", s.handleReverseRequest)

	// Catchall
	s.mux.HandleFunc(".", s.handleForward)

	s.server_udp = &dns.Server{Addr: c.DnsAddr, Net: "udp", Handler: s.mux}
	s.server_tcp = &dns.Server{Addr: c.DnsAddr, Net: "tcp", Handler: s.mux}

	return s, nil
}

func (s *DNSServer) clientLoadResolvconf() {
	resolvconf_path := "/etc/resolv.conf"
	cc, err := dns.ClientConfigFromFile(resolvconf_path)
	if err != nil {
		logger.Errorf("error parsing resolv.conf: %v", err)
	}

	if len(cc.Servers) > 0 {
		logger.Infof("Loaded %d upstream DNS servers from '%s': %s", len(cc.Servers), resolvconf_path, cc.Servers)
	}
}

// Start starts the DNSServer
func (s *DNSServer) Start() error {
	logger.Infof("Starting DNS service; domain='%s' listening on %s/tcp+udp", s.config.Domain.String(), s.config.DnsAddr)

	go func() {
		err := s.server_udp.ListenAndServe()
		if err != nil {
			logger.Fatalf("Error listening for DNS over UDP: %v", err)
		}
	}()

	go func() {
		err := s.server_tcp.ListenAndServe()
		if err != nil {
			logger.Fatalf("Error listening for DNS over TCP: %v", err)
		}
	}()

	return nil
}

// Stop stops the DNSServer
func (s *DNSServer) Stop() {
	s.server_udp.Shutdown()
	s.server_tcp.Shutdown()
}

func (s *DNSServer) getServicePrimary(svc Service) string {
	return utils.DomainJoin(svc.Name, s.config.Domain.String(), "")
}

// AddService adds a new container and thus new DNS records
func (s *DNSServer) AddService(id string, service Service) error {
	if len(service.Primary) == 0 {
		service.Primary = s.getServicePrimary(service)
	}

	if len(service.IPs) == 0 {
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
		return nil
	}

	defer s.lock.Unlock()
	s.lock.Lock()

	id = s.getExpandedID(id)

	logger.Debugf("Adding service=%s id=%s", service.Name, id)

	s.services[id] = &service

	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		logger.Debugf("DNS zone=%s for service=%s", domain, service.Name)
		s.mux.HandleFunc(domain, s.handleRequest)
	}

	logger.Infof("Added service id=%s name=%s", id, service.Name)

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *DNSServer) RemoveService(id string) error {
	id = s.getExpandedID(id)

	service, err := s.GetService(id)
	if err != nil {
		return errors.New("No such service: " + id)
	}

	logger.Debugf("Removing service id=%s name=%s", id, service.Name)

	defer s.lock.Unlock()
	s.lock.Lock()

	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		logger.Debugf("Removing DNS zone=%s for service=%s", domain, service.Name)
		s.mux.HandleRemove(domain)
	}

	delete(s.services, id)

	logger.Infof("Removed service id=%s name=%s", id, service.Name)

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
	for _, nameserver := range s.config.Nameservers {
		logger.Debugf("Forwarding DNS query for domain='%s' to nameserver='%s'", r.Question[0].Name, nameserver)

		in, _, err := s.client.Exchange(r, nameserver)
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
	}

	// Fail
	s.handleFailed(w, r)
}

func (s *DNSServer) handleFailed(w dns.ResponseWriter, r *dns.Msg) {
	dns.HandleFailed(w, r)
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

	logger.Debugf("DNS query '%s' from remote '%s'", query, w.RemoteAddr())

	for service := range s.QueryServices(query) {
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
		logger.Debugf("No DNS record found for query '%s'", query)
		m.Ns = s.createSOA()
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
	}

	w.WriteMsg(m)
}

func (s *DNSServer) handleNxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	//m.RecursionAvailable = true

	m.Ns = s.createSOA()
	m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN

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

	for service := range s.QueryIP(query) {
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
		return
	}

	// We didn't find a record corresponding to the query,
	// try forwarding
	s.handleForward(w, r)
}

func (s *DNSServer) QueryIP(query string) chan *Service {
	c := make(chan *Service, 3)
	reversedIP := strings.TrimSuffix(query, ".in-addr.arpa")
	ip := strings.Join(utils.Reverse(dns.SplitDomainName(reversedIP)), ".")

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
	squery := dns.SplitDomainName(query)

	for domain := range s.ListDomains(suffix, false) {
		sdomain := dns.SplitDomainName(domain)
		if isPrefixQuery(squery, sdomain) {
			return domain
		}
	}
	return ""
}

// QueryServices queries services
func (s *DNSServer) QueryServices(query string) chan *Service {
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
