package edge

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// LoadTLSPair loads a PEM certificate and key and returns the pair with its
// leaf parsed. It is the one loader behind the tls and wss listeners, a tls
// carrier's client certificate and `freesbc check --deploy`, so the check
// opens exactly what run opens. Errors name the failing file when the file
// is the cause; a mismatched pair names neither.
func LoadTLSPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return tls.Certificate{}, err
		}
	}
	return cert, nil
}

// LoadCAPool reads a PEM bundle into a root pool: the tls carrier ca_file.
// A file with no certificate in it is an error.
func LoadCAPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no PEM certificate found")
	}
	return pool, nil
}
