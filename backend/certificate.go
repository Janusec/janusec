/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:46
 * @Last Modified: U2, 2018-07-14 16:21:46
 */

package backend

import (
	"crypto/tls"
	"errors"
	"log"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

var (
	Certs []*models.CertItem
)

func LoadCerts() {
	//fmt.Println("LoadCerts")
	if data.IsMaster {
		Certs = Certs[0:0]
		dbCerts := data.DAL.SelectCertificates()
		for _, dbCert := range dbCerts {
			cert := new(models.CertItem)
			cert.ID = dbCert.ID
			cert.CommonName = dbCert.CommonName
			cert.CertContent = dbCert.CertContent
			pubCert := []byte(cert.CertContent)
			privKey, err := data.AES256Decrypt(dbCert.EncryptedPrivKey, false)
			utils.CheckError("LoadCerts AES256Decrypt", err)
			tlsCert, err := tls.X509KeyPair(pubCert, privKey)
			utils.CheckError("LoadCerts X509KeyPair", err)
			cert.PrivKeyContent = string(privKey)
			cert.TlsCert = tlsCert
			cert.ExpireTime = dbCert.ExpireTime
			if dbCert.Description.Valid == true {
				cert.Description = dbCert.Description.String
			} else {
				cert.Description = ""
			}
			Certs = append(Certs, cert)
		}
	} else {
		// Slave
		rpcCerts := RPCSelectCertificates()
		if rpcCerts != nil {
			Certs = rpcCerts
		}
		//fmt.Println("LoadCerts Slave:", Certs)
	}
}

func GetCertificateByDomain(domain string) (*tls.Certificate, error) {
	if domain_relation, ok := DomainsMap.Load(domain); ok == true {
		certItem := domain_relation.(models.DomainRelation).Cert
		if certItem == nil {
			return nil, errors.New("GetCertificateByDomain Null CertItem: " + domain)
		}
		cert := &(certItem.TlsCert)
		return cert, nil
	} else {
		return nil, errors.New("Unknown Host: " + domain)
	}
}

func GetCertificates() ([]*models.CertItem, error) {
	return Certs, nil
}

func GetCertificateByID(cert_id int64) (*models.CertItem, error) {
	for _, cert := range Certs {
		if cert.ID == cert_id {
			return cert, nil
		}
	}
	return nil, errors.New("Certificate id error.")
}

func GetCertificateByCommonName(commonName string) *models.CertItem {
	for _, cert := range Certs {
		if cert.CommonName == commonName {
			return cert
		}
	}
	log.Println("Get certificate err by common name:", commonName)
	return nil
}

func UpdateCertificate(param map[string]interface{}) (*models.CertItem, error) {
	certificate := param["object"].(map[string]interface{})
	id := int64(certificate["id"].(float64))
	commonName := certificate["common_name"].(string)
	certContent := certificate["cert_content"].(string)
	privKeyContent := certificate["priv_key_content"].(string)
	encryptedPrivKey := data.AES256Encrypt([]byte(privKeyContent), false)
	expireTime := data.GetCertificateExpiryTime(certContent)
	var description string
	var ok bool
	if description, ok = certificate["description"].(string); !ok {
		description = ""
	}
	var certItem *models.CertItem
	tlsCert, err := tls.X509KeyPair([]byte(certContent), []byte(privKeyContent))
	utils.CheckError("UpdateCertificate X509KeyPair", err)
	if err != nil {
		return nil, err
	}
	if id == 0 {
		//new certificate
		newID := data.DAL.InsertCertificate(commonName, certContent, encryptedPrivKey, expireTime, description)
		certItem = new(models.CertItem)
		certItem.ID = newID
		Certs = append(Certs, certItem)
	} else {
		certItem, err = GetCertificateByID(id)
		if err != nil {
			return nil, err
		}
		err = data.DAL.UpdateCertificate(commonName, certContent, encryptedPrivKey, expireTime, description, id)
		if err != nil {
			return nil, err
		}
	}
	certItem.CommonName = commonName
	certItem.CertContent = certContent
	certItem.PrivKeyContent = privKeyContent
	certItem.TlsCert = tlsCert
	certItem.ExpireTime = expireTime
	certItem.Description = description
	data.UpdateBackendLastModified()
	return certItem, nil
}

func GetCertificateIndex(cert_id int64) int {
	for i := 0; i < len(Certs); i++ {
		if Certs[i].ID == cert_id {
			return i
		}
	}
	return -1
}

func DeleteCertificateByID(cert_id int64) error {
	certDomainsCount := data.DAL.SelectDomainsCountByCertID(cert_id)
	if certDomainsCount > 0 {
		return errors.New("This certificate is in use, please delete relevant applications at first.")
	} else {
		err := data.DAL.DeleteCertificate(cert_id)
		if err != nil {
			return err
		}
		i := GetCertificateIndex(cert_id)
		Certs = append(Certs[:i], Certs[i+1:]...)
	}
	data.UpdateBackendLastModified()
	return nil
}
