package http

import (
	//"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/docker/go-connections/nat"
	//"github.com/abursavich/nett"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"
	"github.com/akatrevorjay/doxy/utils/ca"

	"github.com/inconshreveable/go-vhost"
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
	log.Println(msg)
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

func (s *ProxyHttpServer) httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

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

func (s *ProxyHttpServer) httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"

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

// ProxyHTTPServer represents the proxy endpoint
type ProxyHttpServer struct {
	config *utils.Config
	list   *servers.ServiceListProvider

	muxTls  *vhost.TLSMuxer
	muxHttp *vhost.HTTPMuxer

	proxy *Proxy
}

func (s *ProxyHttpServer) tlsSetup() tls.Certificate {
	var dnsNames []string
	dnsNames = append(dnsNames, s.config.Name)
	logger.Debugf("dnsNames: %v", dnsNames)

	// TODO Move this to core, set on Config, along with the next two.
	privBytes, certBytes := ca.ReadOrGenKeyPair(s.config.TlsCaKey, s.config.TlsCert, s.config.TlsGenRsaBits, dnsNames)

	ca, err := tls.X509KeyPair(certBytes, privBytes)
	orPanic(err)

	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	orPanic(err)

	return ca
}

func NewHTTPProxyServer(c *utils.Config, list servers.ServiceListProvider) (*ProxyHttpServer, error) {
	s := &ProxyHttpServer{
		config: c,
		list:   &list,
	}

	ca := s.tlsSetup()

	s.proxy = &Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		},
		Wrap: absolutelyNothingHandler,
		//Timeout: 5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,

		httpDirector:  s.httpDirector,
		httpsDirector: s.httpsDirector,
	}

	return s, nil
}

func absolutelyNothingHandler(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//io.Copy(w, r.Body)
		upstream.ServeHTTP(w, r)
	})
}

// Start starts the http endpoints
func (s *ProxyHttpServer) Start() error {
	logger.Infof("Starting ProxyHttpServer; listening on http=%s https=%s.", s.config.HttpAddr, s.config.HttpsAddr)

	muxTimeout := 1 * time.Hour

	lnHttp, err := net.Listen("tcp", s.config.HttpAddr)
	if err != nil {
		logger.Fatalf("Error listening for http connections: %v", err)
	}
	lnTls, err := net.Listen("tcp", s.config.HttpsAddr)
	if err != nil {
		logger.Fatalf("Error listening for https connections: %v", err)
	}

	muxHttp, err := vhost.NewHTTPMuxer(lnHttp, muxTimeout)
	orPanic(err)
	muxTls, err := vhost.NewTLSMuxer(lnTls, muxTimeout)
	orPanic(err)

	go muxHttp.HandleErrors()
	go muxTls.HandleErrors()

	s.muxHttp = muxHttp
	s.muxTls = muxTls

	lnHttp, err1 := muxHttp.Listen("*.docker")
	lnTls, err2 := muxTls.Listen("*.docker")
	orPanic(err1)
	orPanic(err2)

	go func() {
		var err error

		err = http.Serve(lnHttp, s.proxy)
		orPanic(err)
	}()

	go func() {
		for {
			conn, err := lnTls.Accept()
			if err != nil {
				logger.Errorf("Error accepting conn=%v: %v", conn, err)
				continue
			}

			go func(conn net.Conn) {
				tlsConn, err := vhost.TLS(conn)
				if err != nil {
					logger.Errorf("Error wrapping conn=%v: %v", conn, err)
					panic(err)
				}

				var (
					//origScheme string = "https"
					origAddr string = tlsConn.Host()
					origName string = tlsConn.ClientHelloMsg.ServerName
				)

				if origAddr == "" {
					err = fmt.Errorf("Cannot support non-SNI enabled clients (no tlsConn.Host)")
					//http.Error(w, "no upstream", 503)
					panic(err)
				}

				if origName == "" {
					err = fmt.Errorf("Cannot support non-SNI enabled clients (no tlsConn.ClientHelloMsg.ServerName)")
					//http.Error(w, "no upstream", 503)
					panic(err)
				}

				provisionalCert, err := s.proxy.cert(origName)
				if err != nil {
					logger.Errorf("Cert gen error: %v", err)
					//http.Error(w, "no upstream", 503)
					return
				}

				sConfig := s.proxy.makeTlsConfig(s.proxy.TLSServerConfig)
				sConfig.Certificates = []tls.Certificate{*provisionalCert}
				sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return s.proxy.cert(hello.ServerName)
				}

				tlsConnIn := tls.Server(tlsConn, sConfig)

				// This listener allows us to http.Serve on the upgraded TLS connection
				listener := &mitmListener{tlsConnIn}

				// Serve HTTP requests on the upgraded connection.  This will keep reading
				// requests and sending them through our handler as long as the connection
				// stays open.
				go func() {
					err = http.Serve(listener, s.proxy)
					if err != nil && err != io.EOF {
						logger.Errorf("Error serving mitm'ed connection: %v", err)
					}
				}()
			}(conn)
		}
	}()

	return nil
}

// TODO Look up from DNS
func (s *ProxyHttpServer) adaptDestination(addr string, scheme string) (newAddr string, newScheme string, err error) {
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

		logger.Debugf("Service available by name %s://%s => %s://%s", scheme, addr, newScheme, newAddr)
	}

	return newAddr, newScheme, nil
}

func (s *ProxyHttpServer) addProxyDomain(id string, domain string) {
	// TODO Store for easier lookup

	//ml, err := s.mux.Listen(domain)
	//orPanic(err)

	//go func(vh VirtualHost, ml net.Listener) {
	//    for {
	//        conn, _ := ml.Accept()
	//        go vh.Handle(conn)
	//    }
	//}(vh, ml)
}

func (s *ProxyHttpServer) removeProxyDomain(id string, domain string) {
}

// AddService adds a new container
func (s *ProxyHttpServer) AddService(id string, service *servers.Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", service.Name)
		return nil
	}

	added := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		s.addProxyDomain(id, domain)

		added = append(added, domain)
	}

	logger.Infof("Handling HTTP zones for service=%s: %v", service.Name, added)

	return nil
}

// RemoveService removes a new container
func (s *ProxyHttpServer) RemoveService(id string) error {
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
		if dns.IsSubDomain(s.config.Domain.String(), domain) {
			continue
		}

		s.removeProxyDomain(id, domain)

		removed = append(removed, domain)
	}

	logger.Infof("Removed HTTP zones for service=%s: %v", service.Name, removed)

	return nil
}
