package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
	"net"
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

// ReadOrGenKeyPair Reads or generates a keypair
func ReadOrGenKeyPair(keyfile string, certfile string, bits int, dnsNames []string) ([]byte, []byte) {
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
		cert := genCert(priv, dnsNames, time.Now(), 365*24*time.Hour)

		// Write to files
		writePrivateKey(priv, keyfile)
		writeCertFile(cert, certfile)
	}

	var privBytes, certBytes []byte

	privBytes, certBytes, err = tryRead(keyfile, certfile)
	if err != nil {
		logger.Errorf("Keypair not able to be read, generating one for you.")

		gen(keyfile, certfile, bits)

		privBytes, certBytes, err = tryRead(keyfile, certfile)
		orPanic(err)
	}

	return privBytes, certBytes
}

// makeConfig makes a copy of a tls config if provided. Otherwise returns an
// empty tls config.
func makeConfig(template *tls.Config) *tls.Config {
	tlsConfig := &tls.Config{}
	if template != nil {
		// Copy the provided tlsConfig
		*tlsConfig = *template
	}
	return tlsConfig
}
