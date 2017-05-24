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
	"time"

	"github.com/akatrevorjay/doxy/utils"
	"github.com/akatrevorjay/doxy/utils/ca"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

func (s *ProxyHttpServer) tlsSetup() {
	var dnsNames []string
	dnsNames = append(dnsNames, s.config.Name)

	privBytes, certBytes := ca.ReadOrGenKeyPair(s.config.TlsCaKey, s.config.TlsCert, s.config.TlsGenRsaBits, dnsNames)

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
	mux *vhost.HTTPMuxer
}

func NewHTTPProxyServer(c *utils.Config, list ServiceListProvider) (*ProxyHttpServer, error) {
	s := &ProxyHttpServer{
		config: c,
		list:   &list,
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

		var rhost, host, port string

		rhost = req.URL.Host
		if rhost == "" {
			rhost = req.Host
		}

		host, port, err := net.SplitHostPort(rhost)
		if err != nil {
			host, port = rhost, "80"
		}

		var svc *Service

		if ip := net.ParseIP(host); ip == nil {
			for svc = range (*s.list).QueryServices(host) {
				break
			}

			if svc == nil {
				logger.Errorf("Service not available by name: %v", host)
				//w.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				//req.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				//req.Close = true
				//proxy.ServeHTTP(w, req)
				//proxy.ServeHTTP(w, nil)
				return
			}

			host = svc.IPs[0].String()
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

		//ml, _ := s.mux.Listen(domain)

		//go func(vh virtualHost, ml net.Listener) {
		//    for {
		//        conn, _ := ml.Accept()
		//        go vh.Handle(conn)
		//    }
		//}(vhost, ml)

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

		muxTimeout := 1*time.Hour

		mux, _ := vhost.NewHTTPMuxer(ln, muxTimeout)
		s.mux = mux

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

				var svc *Service
				for svc = range (*s.list).QueryServices(host) {
					break
				}

				if svc == nil {
					logger.Errorf("Service not available by name: %v", host)
					c.Close()
					return
				}

				host = svc.IPs[0].String()
				//host = svc.Primary
				//// trim off any trailing dot
				//if host[len(host)-1] == '.' {
				//    host = host[:len(host)-1]
				//}

				remoteHostport := net.JoinHostPort(host, port)

				//utils.Dump(tlsConn)
				utils.Dump(remoteHostport)

				logger.Debugf("Service available by name: %v", host)

				var method string
				//switch port {
				//    case "443", svc.HttpsPort:
				//        method = "CONNECT"
				//    case svc.HttpPort:
				//        // TODO This won't hold up with POSTs...
				//        method = "GET"
				//}
				method = "CONNECT"

				connectReq := &http.Request{
					Method: method,
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
