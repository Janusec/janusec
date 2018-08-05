/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:56
 * @Last Modified: U2, 2018-07-14 16:20:56
 */

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

type SelfSignedCertificate struct {
	CertContent    string `json:"cert_content"`
	PrivKeyContent string `json:"priv_key_content"`
}

func GenerateRSACertificate(param map[string]interface{}) (selfSignedCert *SelfSignedCertificate, err error) {
	reqObj := param["object"].(map[string]interface{})
	commonName := reqObj["common_name"].(string)
	org := strings.ToUpper(commonName)
	dotIndex := strings.Index(org, ".")
	if dotIndex > 0 {
		org = org[dotIndex+1:]
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(3653 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	//fmt.Println("derBytes=", derBytes)
	if err != nil {
		return nil, err
	}
	pubCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	selfSignedCert = &SelfSignedCertificate{CertContent: string(pubCertBytes), PrivKeyContent: string(privKeyBytes)}
	return selfSignedCert, nil
}
