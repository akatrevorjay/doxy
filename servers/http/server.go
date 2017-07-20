package http

import (
	//"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"

	//"github.com/abursavich/nett"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"
	"github.com/akatrevorjay/doxy/utils/ca"

	"github.com/gorilla/mux"
	"github.com/inconshreveable/go-vhost"
)

// HTTPProxy represents the proxy endpoint
type HTTPProxy struct {
	config *utils.Config
	list   *servers.ServiceListProvider
	mux    *mux.Router
	proxy *Proxy
}

func (s *HTTPProxy) tlsSetup() tls.Certificate {
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

func NewHTTPProxy(c *utils.Config, list servers.ServiceListProvider) (*HTTPProxy, error) {
	s := &HTTPProxy{
		config: c,
		list:   &list,
	}

	ca := s.tlsSetup()

	s.proxy = &Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
			//    tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				//tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			//    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			//    tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			//    tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				//tls.TLS_RSA_WITH_RC4_128_SHA,
			//    tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			//    tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			//    tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			//    tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			//    tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			//    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			//    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			//    tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			//    tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			//    tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			//    tls.TLS_FALLBACK_SCSV,
			},
			//PreferServerCipherSuites: true,
		},
		Wrap: absolutelyNothingHandler,
		//Timeout: 5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,

		httpDirector:  s.httpDirector,
		httpsDirector: s.httpsDirector,
	}

	mux := mux.NewRouter()
	s.mux = mux

	doxy_host := utils.DomainJoin(s.config.Name, s.config.Domain.String())

	doxymux := s.mux.Host(doxy_host).Subrouter()
	doxymux.HandleFunc("/pac.js", s.handlePAC)

	s.mux.HandleFunc("/_doxy/pac.js", s.handlePAC)

	//s.mux.Handle("/_doxy/", s.handleDoxy)

	// Pass the rest to proxy
	s.mux.Handle("/", s.proxy)

	return s, nil
}

// Start starts the http endpoints
func (s *HTTPProxy) Start() error {
	logger.Infof("Starting HTTPProxy; listening on http=%s https=%s.", s.config.HttpAddr, s.config.HttpsAddr)

	// HTTP
	lnHttp, err := net.Listen("tcp", s.config.HttpAddr)
	if err != nil {
		logger.Fatalf("Error listening for http connections: %v", err)
	}

	// HTTP serve
	go func() {
		var err error

		//err = http.Serve(lnHttp, s.proxy)
		err = http.Serve(lnHttp, s.mux)
		orPanic(err)
	}()

	// TLS
	lnTls, err := net.Listen("tcp", s.config.HttpsAddr)
	if err != nil {
		logger.Fatalf("Error listening for https connections: %v", err)
	}

	// TLS serve
	// This is different from the proxy handler as it generates certificates on the fly providing TLS
	// for all services automatically.
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
					//err = http.Serve(listener, s.proxy)
					err = http.Serve(listener, s.mux)
					if err != nil && err != io.EOF {
						logger.Errorf("Error serving mitm'ed connection: %v", err)
					}
				}()
			}(conn)
		}
	}()

	return nil
}

func (s *HTTPProxy) addProxyDomain(id string, domain string) {
	// TODO Store for easier lookup
}

func (s *HTTPProxy) removeProxyDomain(id string, domain string) {
}

// AddService adds a new container
func (s *HTTPProxy) AddService(id string, service *servers.Service) error {
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
func (s *HTTPProxy) RemoveService(id string) error {
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
