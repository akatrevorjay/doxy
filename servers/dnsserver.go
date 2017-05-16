/* dnsserver.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package servers

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/akatrevorjay/doxy/utils"
	"github.com/miekg/dns"
)

// DNSServer represents a DNS server
type DNSServer struct {
	config    *utils.Config
	serverUdp *dns.Server
	serverTcp *dns.Server
	mux       *dns.ServeMux
	lock      *sync.RWMutex
	client    *dns.Client
	list      *ServiceListProvider
}

// NewDNSServer create a new DNSServer
func NewDNSServer(c *utils.Config, list ServiceListProvider) (*DNSServer, error) {
	s := &DNSServer{
		config: c,
		lock:   &sync.RWMutex{},
		client: &dns.Client{
			// Suppress multiple outstanding queries (with the same question, type and class)
			SingleInflight: true,
		},
		list: &list,
	}

	s.clientLoadResolvconf()

	s.mux = dns.NewServeMux()

	s.mux.HandleFunc(c.Domain.String()+".", s.handleRequest)
	s.mux.HandleFunc("in-addr.arpa.", s.handleReverseRequest)

	// Catchall
	s.mux.HandleFunc(".", s.handleForward)

	s.serverUdp = &dns.Server{Addr: c.DnsAddr, Net: "udp", Handler: s.mux}
	s.serverTcp = &dns.Server{Addr: c.DnsAddr, Net: "tcp", Handler: s.mux}

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
		err := s.serverUdp.ListenAndServe()
		if err != nil {
			logger.Fatalf("Error listening for DNS over UDP: %v", err)
		}
	}()

	go func() {
		err := s.serverTcp.ListenAndServe()
		if err != nil {
			logger.Fatalf("Error listening for DNS over TCP: %v", err)
		}
	}()

	return nil
}

// Stop stops the DNSServer
func (s *DNSServer) Stop() {
	s.serverUdp.Shutdown()
	s.serverTcp.Shutdown()
}

// AddService adds a new container and thus new DNS records
func (s *DNSServer) AddService(id string, service *Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
		return nil
	}

	defer s.lock.Unlock()
	s.lock.Lock()

	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		logger.Debugf("DNS zone=%s for service=%s", domain, service.Name)
		s.mux.HandleFunc(domain, s.handleRequest)
	}

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *DNSServer) RemoveService(id string) error {
	service, err := (*s.list).GetService(id)
	if err != nil {
		logger.Errorf("Cannot remove a service that doesn't already exist. id=%s", id)
		return nil
	}

	if len(service.IPs) == 0 {
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
		return nil
	}

	defer s.lock.Unlock()
	s.lock.Lock()

	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		logger.Debugf("Removing DNS zone=%s for service=%s", domain, service.Name)
		s.mux.HandleRemove(domain)
	}

	return nil
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

	m.Answer = make([]dns.RR, 0)

	logger.Debugf("DNS query %v from remote %v", r.Question[0].Name, w.RemoteAddr())

	for svc := range (*s.list).QueryServices(r.Question[0].Name) {
		var rr dns.RR
		switch r.Question[0].Qtype {

		case dns.TypeA:
			if r.Question[0].Name != svc.Primary {
				rr = s.makeServiceCNAME(r.Question[0].Name, svc)
				m.Answer = append(m.Answer, rr)
			}
			rr = s.makeServiceA(svc.Primary, svc)

		case dns.TypeMX:
			rr = s.makeServiceMX(r.Question[0].Name, svc)

		default:
			logger.Debugf("Query type not supported: %v", r.Question[0].Qtype)
			// this query type isn't supported, but we do have
			// a record with this name. Per RFC 4074 sec. 3, we
			// immediately return an empty NOERROR reply.
			m.Ns = s.createSOA()
			m.MsgHdr.Authoritative = true
			w.WriteMsg(m)
			return

		}

		m.Answer = append(m.Answer, rr)
	}

	// We didn't find a record corresponding to the query
	if len(m.Answer) == 0 {
		logger.Debugf("No DNS record found for query '%s'", r.Question[0].Name)
		m.Ns = s.createSOA()
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
	}

	for _, rr := range m.Answer {
		logger.Debugf("%s: %v", r.Question[0].Name, rr)
	}

	//utils.Dump(m)

	w.WriteMsg(m)
}

func (s *DNSServer) handleNxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

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
	reversedIP := strings.TrimSuffix(query, ".in-addr.arpa")
	ipstr := strings.Join(utils.Reverse(dns.SplitDomainName(reversedIP)), ".")

	ip := net.ParseIP(ipstr)

	return (*s.list).QueryServicesByIP(ip)
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
// one exception to accomodate the desired behavior we wish from doxy,
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
