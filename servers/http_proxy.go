package servers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/akatrevorjay/doxy/utils"
	"github.com/elazarl/goproxy"
	vhost "github.com/inconshreveable/go-vhost"
)

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}

	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa

	goproxy.OkConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectAccept,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa),
	}

	goproxy.MitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa),
	}

	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectHTTPMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa),
	}

	goproxy.RejectConnect = &goproxy.ConnectAction{
		Action:    goproxy.ConnectReject,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa),
	}

	return nil
}

// ProxyHTTPServer represents the proxy endpoint
type ProxyHttpServer struct {
	config *utils.Config
	list   *ServiceListProvider
	server *goproxy.ProxyHttpServer
}

func NewHTTPProxyServer(c *utils.Config, list ServiceListProvider) (*ProxyHttpServer, error) {
	s := &ProxyHttpServer{
		config: c,
		list:   &list,
	}

	setCA(caCert, caKey)

	proxy := goproxy.NewProxyHttpServer()

	proxy.Verbose = c.Verbose
	//proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()
			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

			remote, err := connectDial(proxy, "tcp", req.URL.Host)
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
			remoteHostport := net.JoinHostPort(host, port)

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
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
		return nil
	}

	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		logger.Debugf("http/s domain=%s for service=%s", domain, service.Name)
		//s.AddProxyDomain(domain)
	}

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
		logger.Warningf("Service '%s' ignored: No IP provided:", id, id)
		return nil
	}

	for domain := range service.ListDomains(s.config.Domain.String(), false) {
		logger.Debugf("Removing http/s domain=%s for service=%s", domain, service.Name)
		//s.RemoveProxyDomain(domain)
	}

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

				connectReq := &http.Request{
					Method: "CONNECT",
					URL: &url.URL{
						Opaque: tlsConn.Host(),
						Host:   net.JoinHostPort(tlsConn.Host(), "443"),
					},
					Host:   tlsConn.Host(),
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
