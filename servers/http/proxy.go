package http

import (
	//"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/docker/go-connections/nat"
	//"github.com/abursavich/nett"
)

const (
	CONNECT = "CONNECT"
)

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	// TLSServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	TLSServerConfig *tls.Config

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	TLSClientConfig *tls.Config

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	Wrap func(upstream http.Handler) http.Handler

	//Timeout time.Duration
	TLSHandshakeTimeout time.Duration

	httpDirector  func(*http.Request)
	httpsDirector func(*http.Request)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Make it appear like a proxied request
	if r.Method == CONNECT {
		r.URL.Scheme = "https"
	} else {
		r.URL.Scheme = "http"
	}
	r.URL.Host = r.Host

	logger.Debugf("Request: %v", r)

	if r.Method == CONNECT {
		p.serveConnect(w, r)
		return
	}

	//dialer := &nett.Dialer{
	//    // Cache successful DNS lookups for five minutes
	//    // using DefaultResolver to fill the cache.
	//    Resolver: &nett.CacheResolver{TTL: 5 * time.Minute},
	//    // Concurrently dial an IPv4 and an IPv6 address and
	//    // return the connection that is established first.
	//    IPFilter: nett.DualStack,
	//    // Give up after ten seconds including DNS resolution.
	//    Timeout: 10 * time.Second,
	//}

	rp := &httputil.ReverseProxy{
		Director:      p.httpDirector,
		FlushInterval: p.FlushInterval,
		Transport: &http.Transport{
			//DialTLS:             dialer.Dial,
			//Dial:                dialer.Dial,
			TLSHandshakeTimeout: p.TLSHandshakeTimeout,
		},
	}

	p.Wrap(rp).ServeHTTP(w, r)
}

// makeConfig makes a copy of a tls config if provided. Otherwise returns an
// empty tls config.
func (p *Proxy) makeTlsConfig(template *tls.Config) *tls.Config {
	tlsConfig := &tls.Config{}
	if template != nil {
		// Copy the provided tlsConfig
		*tlsConfig = *template
	}
	return tlsConfig
}

func respBadGateway(resp http.ResponseWriter, msg string) {
	logger.Warningf("msg=%v", msg)
	resp.WriteHeader(502)
	resp.Write([]byte(msg))
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		sconn *tls.Conn
		name  = dnsName(r.Host)
	)

	if name == "" {
		logger.Infof("cannot determine cert name for %v", r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	provisionalCert, err := p.cert(name)
	if err != nil {
		logger.Errorf("cert error: %v", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*sConfig = *p.TLSServerConfig
	}

	sConfig.Certificates = []tls.Certificate{*provisionalCert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		if p.TLSClientConfig != nil {
			*cConfig = *p.TLSClientConfig
		}
		cConfig.ServerName = hello.ServerName
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			logger.Infof("dial", r.Host, err)
			return nil, err
		}
		return p.cert(hello.ServerName)
	}

	cconn, err := handshake(w, sConfig)
	if err != nil {
		logger.Infof("handshake", r.Host, err)
		return
	}
	defer cconn.Close()
	if sconn == nil {
		logger.Infof("could not determine cert name for " + r.Host)
		return
	}
	defer sconn.Close()

	od := &oneShotDialer{c: sconn}
	rp := &httputil.ReverseProxy{
		Director: p.httpsDirector,
		Transport: &http.Transport{
			DialTLS:             od.Dial,
			Dial:                od.Dial,
			TLSHandshakeTimeout: p.TLSHandshakeTimeout,
		},
		FlushInterval: p.FlushInterval,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, p.Wrap(rp))
	<-ch
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	return genCert(p.CA, names)
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// namesOnCert returns the dns names
// in the peer's presented cert.
func namesOnCert(conn *tls.Conn) []string {
	// TODO(kr): handle IP addr SANs.
	c := conn.ConnectionState().PeerCertificates[0]
	if len(c.DNSNames) > 0 {
		// If Subject Alt Name is given,
		// we ignore the common name.
		// This matches behavior of crypto/x509.
		return c.DNSNames
	}
	return []string{c.Subject.CommonName}
}

// A oneShotDialer implements net.Dialer whos Dial only returns a
// net.Conn as specified by c followed by an error for each subsequent Dial.
type oneShotDialer struct {
	c  net.Conn
	mu sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return nil, fmt.Errorf("closed %v network=%v addr=%v", d, network, addr)
	}
	c := d.c
	d.c = nil
	return c, nil
}

// A oneShotListener implements net.Listener whos Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, fmt.Errorf("closed %v", l)
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}

func absolutelyNothingHandler(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//io.Copy(w, r.Body)
		upstream.ServeHTTP(w, r)
	})
}

func (s *HTTPProxy) httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

	s.adaptDestinationRequest(r)
}

func (s *HTTPProxy) httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"

	s.adaptDestinationRequest(r)
}

func (s *HTTPProxy) adaptDestinationRequest(r *http.Request) {
	var (
		origScheme string = r.URL.Scheme
		origAddr   string = r.URL.Host
		err        error
	)

	if origAddr == "" {
		err = fmt.Errorf("Cannot support requests without a Host (origAddr=%v)", origAddr)
		//http.Error(w, "no upstream", 503)
		panic(err)
	}

	addr, scheme, err := s.adaptDestination(origAddr, origScheme)
	if err != nil {
		err = fmt.Errorf("Failed to adapt destination %s://%s: %v", origScheme, origAddr, err)
		panic(err)
	}

	//logger.Debugf("New connection %v => %s://%s", conn.RemoteAddr(), scheme, addr)

	// Fix up the request URL to make it look as it would have if the client
	// thought it were talking to a proxy at this point.
	r.URL.Scheme = scheme
	r.Host = addr
	r.URL.Host = r.Host
}

// TODO Look up from DNS
func (s *HTTPProxy) adaptDestination(addr string, scheme string) (newAddr string, newScheme string, err error) {
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
