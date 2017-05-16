package servers

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/akatrevorjay/doxy/utils"
	"github.com/elazarl/goproxy"
	vhost "github.com/inconshreveable/go-vhost"
)

func genPrivateKey(rsaBits int) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	orPanic(err)
	return priv
}

func genCert(priv *rsa.PrivateKey, dnsNames []string, validFrom time.Time, validDuration time.Duration) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	orPanic(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Doxy"},
		},
		NotBefore: validFrom,
		NotAfter:  validFrom.Add(validDuration),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	for _, h := range dnsNames {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	orPanic(err)

	cert, err := x509.ParseCertificate(derBytes)
	orPanic(err)

	return cert
}

func pemBlockForPrivateKey(priv *rsa.PrivateKey) *pem.Block {
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}

	return pemBlock
}

func pemBlockForPublicKey(pub *rsa.PublicKey) *pem.Block {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		orPanic(err)
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}

	return pemBlock
}

func writePrivateKey(priv *rsa.PrivateKey, file string) {
	out, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	orPanic(err)

	pem.Encode(
		out,
		pemBlockForPrivateKey(priv),
	)

	out.Close()

	logger.Infof("Wrote private key to file %v", file)
}

func writeCertFile(cert *x509.Certificate, file string) {
	derBytes := cert.Raw

	out, err := os.Create(file)
	orPanic(err)

	pem.Encode(
		out,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)

	out.Close()

	logger.Infof("Wrote certificate to file %v", file)
}

func (s *ProxyHttpServer) readOrGenKeyPair() ([]byte, []byte) {
	var err error

	tryRead := func(keyfile string, certfile string) ([]byte, []byte, error) {
		logger.Debugf("Reading keypair from keyfile=%v certfile=%v", keyfile, certfile)

		var privBytes, certBytes []byte
		var err1, err2 error

		privBytes, err1 = ioutil.ReadFile(keyfile)
		certBytes, err2 = ioutil.ReadFile(certfile)
		if err1 != nil || err2 != nil {
			err := fmt.Errorf("Failed to load keypair keyfile=%v certfile=%v", keyfile, certfile)
			return nil, nil, err
		}

		logger.Infof("Read keypair from keyfile=%v certfile=%v", keyfile, certfile)
		return privBytes, certBytes, nil
	}

	gen := func(keyfile string, certfile string, bits int) {
		logger.Infof("Generating keypair keyfile=%v certfile=%v", keyfile, certfile)

		// Generate key
		priv := genPrivateKey(bits)

		// Generate cert
		var dnsNames []string
		dnsNames = append(dnsNames, s.config.Name)

		cert := genCert(priv, dnsNames, time.Now(), 365*24*time.Hour)

		// Write to files
		writePrivateKey(priv, keyfile)
		writeCertFile(cert, certfile)
	}

	var privBytes, certBytes []byte

	privBytes, certBytes, err = tryRead(s.tlsKeyFile, s.tlsCertFile)
	if err != nil {
		logger.Errorf("Keypair not able to be read, generating one for you.")

		gen(s.tlsKeyFile, s.tlsCertFile, s.tlsKeyGenRsaBits)

		privBytes, certBytes, err = tryRead(s.tlsKeyFile, s.tlsCertFile)
		orPanic(err)
	}

	return privBytes, certBytes
}

func (s *ProxyHttpServer) tlsSetup() {
	privBytes, certBytes := s.readOrGenKeyPair()

	ca, err := tls.X509KeyPair(certBytes, privBytes)
	orPanic(err)

	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	orPanic(err)

	goproxy.GoproxyCa = ca

	goproxy.OkConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectAccept,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}

	goproxy.MitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}

	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectHTTPMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}

	goproxy.RejectConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectReject,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}
}

// ProxyHTTPServer represents the proxy endpoint
type ProxyHttpServer struct {
	config *utils.Config
	list   *ServiceListProvider
	server *goproxy.ProxyHttpServer

	tlsKeyFile  string
	tlsCertFile string

	tlsKeyGenRsaBits int
}

func NewHTTPProxyServer(c *utils.Config, list ServiceListProvider) (*ProxyHttpServer, error) {
	s := &ProxyHttpServer{
		config: c,
		list:   &list,

		tlsKeyFile:  "/app/certs/ca.key",
		tlsCertFile: "/app/certs/ca.crt",

		tlsKeyGenRsaBits: 4096,
	}

	s.tlsSetup()

	proxy := goproxy.NewProxyHttpServer()

	proxy.Verbose = c.Verbose

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logger.Debugf("NonproxyHandler w=%v req=%v", w, req)

		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		host, port, err := net.SplitHostPort(req.URL.Host)
		if err != nil {
			host, port = req.URL.Host, "80"
		}

		var svc *Service
		for svc = range (*s.list).QueryServices(host) {
			break
		}

		if svc == nil {
			logger.Errorf("Service not available by name: %v", host)
			//req.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
			//req.Close = true
			proxy.ServeHTTP(w, nil)
			return
		}

		host = svc.IPs[0].String()
		// trim off any trailing dot
		if host[len(host)-1] == '.' {
			host = host[:len(host)-1]
		}

		remoteHostport := net.JoinHostPort(host, port)

		utils.Dump(req)
		utils.Dump(remoteHostport)

		logger.Debugf("Service available by name: %v", host)

		// TODO Look up from DNS
		//remote, err := connectDial(proxy, "tcp", remoteHostport
		//orPanic(err)

		req.URL.Host = host

		req.URL.Scheme = "http"
		//req.URL.Host = req.Host

		proxy.ServeHTTP(w, req)
	})

	//proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	//proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
	//    HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			logger.Debugf("OnRequest match=.*:80 req=%v client=%v ctx=%v", req, client, ctx)

			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()
			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

			host, port, err := net.SplitHostPort(req.URL.Host)
			if err != nil {
				host, port = req.URL.Host, "80"
			}

			var svc *Service
			for svc = range (*s.list).QueryServices(host) {
				break
			}

			if svc == nil {
				logger.Errorf("Service not available by name: %v", host)
				//req.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				//req.Close = true
				//proxy.ServeHTTP(w, nil)
				return
			}

			host = svc.IPs[0].String()
			// trim off any trailing dot
			if host[len(host)-1] == '.' {
				host = host[:len(host)-1]
			}

			remoteHostport := net.JoinHostPort(host, port)

			utils.Dump(req)
			utils.Dump(remoteHostport)

			logger.Debugf("Service available by name: %v", host)

			// TODO Look up from DNS
			remote, err := connectDial(proxy, "tcp", remoteHostport)
			orPanic(err)

			remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
			for {
				req, err := http.ReadRequest(clientBuf.Reader)
				orPanic(err)
				orPanic(req.Write(remoteBuf))
				orPanic(remoteBuf.Flush())
				resp, err := http.ReadResponse(remoteBuf.Reader, req)
				orPanic(err)
				orPanic(resp.Write(clientBuf.Writer))
				orPanic(clientBuf.Flush())
			}
		})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:443$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			logger.Debugf("OnRequest match=.*:443 req=%v client=%v ctx=%v", req, client, ctx)

			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()
			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

			host, port, err := net.SplitHostPort(req.URL.Host)
			if err != nil {
				host, port = req.URL.Host, "80"
			}

			var svc *Service
			for svc = range (*s.list).QueryServices(host) {
				break
			}

			if svc == nil {
				logger.Errorf("Service not available by name: %v", host)
				//req.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				//req.Close = true
				//proxy.ServeHTTP(w, nil)
				return
			}

			host = svc.IPs[0].String()
			// trim off any trailing dot
			if host[len(host)-1] == '.' {
				host = host[:len(host)-1]
			}

			remoteHostport := net.JoinHostPort(host, port)

			utils.Dump(req)
			utils.Dump(remoteHostport)

			logger.Debugf("Service available by name: %v", host)

			// TODO Look up from DNS
			remote, err := connectDial(proxy, "tcp", remoteHostport)
			orPanic(err)

			remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
			for {
				req, err := http.ReadRequest(clientBuf.Reader)
				orPanic(err)
				orPanic(req.Write(remoteBuf))
				orPanic(remoteBuf.Flush())
				resp, err := http.ReadResponse(remoteBuf.Reader, req)
				orPanic(err)
				orPanic(resp.Write(clientBuf.Writer))
				orPanic(clientBuf.Flush())
			}
		})

	s.server = proxy
	return s, nil
}

// AddService adds a new container and thus new DNS records
func (s *ProxyHttpServer) AddService(id string, service *Service) error {
	if len(service.IPs) == 0 {
		logger.Warningf("Service %s ignored: No IP provided:", service.Name)
		return nil
	}

	added := make([]string, 0)
	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		//s.AddProxyDomain(domain)

		added = append(added, domain)
	}
	logger.Infof("Handling HTTP zones for service=%s: %v", service.Name, added)

	return nil
}

// RemoveService removes a new container and thus DNS records
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
		//s.RemoveProxyDomain(domain)

		removed = append(removed, domain)
	}
	logger.Infof("Removed HTTP zones for service=%s: %v", service.Name, removed)

	return nil
}

// Start starts the http endpoints
func (s *ProxyHttpServer) Start() error {
	logger.Infof("Starting ProxyHttpServer; listening on http=%s https=%s.", s.config.HttpAddr, s.config.HttpsAddr)

	go func() {
		// listen to the TLS ClientHello but make it a CONNECT request instead
		ln, err := net.Listen("tcp", s.config.HttpsAddr)
		if err != nil {
			logger.Fatalf("Error listening for https connections - %v", err)
		}

		for {
			c, err := ln.Accept()
			if err != nil {
				logger.Errorf("Error accepting new connection - %v", err)
				continue
			}

			go func(c net.Conn) {
				tlsConn, err := vhost.TLS(c)
				if err != nil {
					logger.Errorf("Error accepting new connection - %v", err)
				}

				if tlsConn.Host() == "" {
					logger.Errorf("Cannot support non-SNI enabled clients")
					return
				}

				host, port, err := net.SplitHostPort(tlsConn.Host())
				if err != nil {
					host, port = tlsConn.Host(), "80"
				}

				ok := false
				for svc := range (*s.list).QueryServices(host) {
					host = svc.IPs[0].String()

					ok = true
					break
				}

				if !ok {
					logger.Errorf("Service not available by name: %v", host)
					//req.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
					//req.Close = true
					//proxy.ServeHTTP(w, nil)
					return
				}

				// trim off any trailing dot
				if host[len(host)-1] == '.' {
					host = host[:len(host)-1]
				}

				remoteHostport := net.JoinHostPort(host, port)

				//utils.Dump(tlsConn)
				utils.Dump(remoteHostport)

				logger.Debugf("Service available by name: %v", host)

				connectReq := &http.Request{
					Method: "CONNECT",
					URL: &url.URL{
						Opaque: host,
						Host:   remoteHostport,
					},
					Host:   host,
					Header: make(http.Header),
				}

				resp := dumbResponseWriter{tlsConn}
				s.server.ServeHTTP(resp, connectReq)
			}(c)
		}
	}()

	go func() {
		err := http.ListenAndServe(s.config.HttpAddr, s.server)
		if err != nil {
			logger.Fatalf("Error listening for http connections - %v", err)
		}
	}()

	return nil
}

// copied/converted from https.go
func dial(proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.Tr.Dial != nil {
		return proxy.Tr.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

// copied/converted from https.go
func connectDial(proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDial == nil {
		return dial(proxy, network, addr)
	}
	return proxy.ConnectDial(network, addr)
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
