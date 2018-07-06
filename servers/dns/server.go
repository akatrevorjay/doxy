/* dnsserver.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package dns

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"
	"github.com/miekg/dns"
)

// DnsServer represents a DNS server
type DnsServer struct {
	config    *utils.Config
	serverUdp *dns.Server
	serverTcp *dns.Server
	mux       *dns.ServeMux
	lock      *sync.RWMutex
	client    *dns.Client
	list      *servers.ServiceListProvider
	IsProxy	  bool
}

// NewDnsServer create a new DnsServer
func NewDnsServer(c *utils.Config, list servers.ServiceListProvider) (*DnsServer, error) {
	s := &DnsServer{
		config: c,
		lock:   &sync.RWMutex{},
		client: &dns.Client{
			// Suppress multiple outstanding queries (with the same question, type and class)
			SingleInflight: true,
		},
		list: &list,
		IsProxy: c.ProxyDNS,
	}

	s.mux = dns.NewServeMux()

	s.mux.HandleFunc(c.Domain.String()+".", s.handleRequest)
	s.mux.HandleFunc("in-addr.arpa.", s.handleReverseRequest)

	if (s.IsProxy) {
		if (c.ProxyNameserversFromResolvconf) {
			s.clientLoadResolvconf()
		}
	}

	// Catchall
	s.mux.HandleFunc(".", s.handleForward)

	s.serverUdp = &dns.Server{Addr: c.DnsAddr, Net: "udp", Handler: s.mux}
	s.serverTcp = &dns.Server{Addr: c.DnsAddr, Net: "tcp", Handler: s.mux}

	return s, nil
}

func (s *DnsServer) clientLoadResolvconf() {
	var resolvconf string = "/etc/resolv.conf"

	cc, err := dns.ClientConfigFromFile(resolvconf)
	if err != nil {
		logger.Errorf("error parsing resolv.conf: %v", err)
	}

	if len(cc.Servers) > 0 {
		logger.Infof("Loaded %d upstream DNS servers from %s: %s", len(cc.Servers), resolvconf, cc.Servers)
	}
}

// Start starts the DnsServer
func (s *DnsServer) Start() error {
	logger.Infof("Starting DnsServer; domain=%s listening on %s/tcp+udp", s.config.Domain.String(), s.config.DnsAddr)

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

// Stop stops the DnsServer
func (s *DnsServer) Stop() {
	s.serverUdp.Shutdown()
	s.serverTcp.Shutdown()
}

// AddService adds a new container and thus new DNS records
func (s *DnsServer) AddService(id string, service *servers.Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided.", service.Name)
		return nil
	}

	defer s.lock.Unlock()
	s.lock.Lock()

	added := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		s.mux.HandleFunc(domain, s.handleRequest)

		added = append(added, domain)
	}
	logger.Infof("Handling DNS zones for service=%s: %v", service.Name, added)

	return nil
}

// RemoveService removes a new container and thus DNS records
func (s *DnsServer) RemoveService(id string) error {
	service, err := (*s.list).GetService(id)
	if err != nil {
		logger.Errorf("Cannot remove a service that doesn't already exist. id=%s", id)
		return nil
	}

	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", id, id)
		return nil
	}

	defer s.lock.Unlock()
	s.lock.Lock()

	removed := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), true) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		s.mux.HandleRemove(domain)

		removed = append(removed, domain)
	}
	logger.Infof("Removed DNS zones for service=%s: %v", service.Name, removed)

	return nil
}

func (s *DnsServer) handleForward(w dns.ResponseWriter, r *dns.Msg) {
	if (s.IsProxy) {
		for _, nameserver := range s.config.Nameservers {
			logger.Debugf("Forwarding DNS query for domain=%s to nameserver=%s", r.Question[0].Name, nameserver)

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
	}

	// Fail
	s.handleFailed(w, r)
}

func (s *DnsServer) handleFailed(w dns.ResponseWriter, r *dns.Msg) {
	dns.HandleFailed(w, r)
}

func (s *DnsServer) makeServiceA(n string, service *servers.Service) dns.RR {
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
			logger.Warningf("Multiple IP address found for container %s. Only the first address will be used", service.Name)
		}
		rr.A = service.IPs[0]
	} else {
		logger.Errorf("No valid IP address found for container %s ", service.Name)
	}

	return rr
}

func (s *DnsServer) makeServiceMX(n string, service *servers.Service) dns.RR {
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

func (s *DnsServer) makeServiceCNAME(n string, service *servers.Service) dns.RR {
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

func (s *DnsServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if (s.IsProxy) {
		m.RecursionAvailable = true
	}

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

	logger.Debugf("DNS query %v from remote %v", r.Question[0].Name, w.RemoteAddr())

	var svc *servers.Service
	for svc = range (*s.list).QueryServices(r.Question[0].Name) {
		break
	}

	// We didn't find a record corresponding to the query
	if svc == nil {
		logger.Debugf("DNS record *not* found for query %s from remote %v", r.Question[0].Name, w.RemoteAddr())

		// m.Answer = make([]dns.RR, 0)

		m.Ns = s.createSOA()

		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN

		// utils.Dump(r.Question)
		utils.Dump(m)

		w.WriteMsg(m)
		return
	}

	m.Answer = make([]dns.RR, 0)
	var rr dns.RR

	switch r.Question[0].Qtype {
	case dns.TypeA:
		if r.Question[0].Name != svc.Primary {
			rr = s.makeServiceCNAME(r.Question[0].Name, svc)
			m.Answer = append(m.Answer, rr)
		}

		rr = s.makeServiceA(svc.Primary, svc)
		m.Answer = append(m.Answer, rr)

	case dns.TypeMX:
		rr = s.makeServiceMX(r.Question[0].Name, svc)
		m.Answer = append(m.Answer, rr)

	default:
		qtype_name := dns.TypeToString[r.Question[0].Qtype]

		logger.Debugf("Query type not supported: %s (%v)", qtype_name, r.Question[0].Qtype)

		utils.Dump(r.Question)

		// this query type isn't supported, but we do have
		// a record with this name. Per RFC 4074 sec. 3, we
		// immediately return an empty NOERROR reply.
		m.MsgHdr.Authoritative = true
		w.WriteMsg(m)
		return

	}

	for _, rr := range m.Answer {
		logger.Debugf("%s: %v", r.Question[0].Name, rr)
	}

	//utils.Dump(m)
	w.WriteMsg(m)
}

func (s *DnsServer) handleNxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if (s.IsProxy) {
		m.RecursionAvailable = true
	}

	m.Ns = s.createSOA()
	m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN

	w.WriteMsg(m)
}

func (s *DnsServer) handleReverseRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if (s.IsProxy) {
		m.RecursionAvailable = true
	}

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

func (s *DnsServer) QueryIP(query string) chan *servers.Service {
	reversedIP := strings.TrimSuffix(query, ".in-addr.arpa")
	ipstr := strings.Join(utils.Reverse(dns.SplitDomainName(reversedIP)), ".")

	ip := net.ParseIP(ipstr)

	return (*s.list).QueryServicesByIP(ip)
}

// TTL is used from config so that not-found result responses are not cached
// for a long time. The other defaults left as is(skydns source) because they
// do not have an use case in this situation.
func (s *DnsServer) createSOA() []dns.RR {
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
