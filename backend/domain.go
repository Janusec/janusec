/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:22:10
 * @Last Modified: U2, 2018-07-14 16:22:10
 */

package backend

import (
	"sync"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	Domains    []*models.Domain
	DomainsMap sync.Map //DomainsMap (string, models.DomainRelation)
)

func LoadDomains() {
	Domains = Domains[0:0]
	DomainsMap.Range(func(key, value interface{}) bool {
		DomainsMap.Delete(key)
		return true
	})
	var dbDomains []*models.DBDomain
	if data.IsPrimary {
		dbDomains = data.DAL.SelectDomains()
	} else {
		dbDomains = RPCSelectDomains()
	}
	for _, dbDomain := range dbDomains {
		pApp, _ := GetApplicationByID(dbDomain.AppID)
		pCert, _ := SysCallGetCertByID(dbDomain.CertID)
		domain := &models.Domain{
			ID:       dbDomain.ID,
			Name:     dbDomain.Name,
			AppID:    dbDomain.AppID,
			CertID:   dbDomain.CertID,
			Redirect: dbDomain.Redirect,
			Location: dbDomain.Location,
			App:      pApp,
			Cert:     pCert}
		Domains = append(Domains, domain)
		DomainsMap.Store(domain.Name, models.DomainRelation{App: pApp, Cert: pCert, Redirect: dbDomain.Redirect, Location: dbDomain.Location})
	}
}

func GetDomainByID(id int64) *models.Domain {
	for _, domain := range Domains {
		if domain.ID == id {
			return domain
		}
	}
	return nil
}

func GetDomainByName(domain_name string) *models.Domain {
	for _, domain := range Domains {
		if domain.Name == domain_name {
			return domain
		}
	}
	return nil
}

func UpdateDomain(app *models.Application, domainMapInterface interface{}) *models.Domain {
	var domainMap = domainMapInterface.(map[string]interface{})
	domainID := int64(domainMap["id"].(float64))
	domainName := domainMap["name"].(string)
	certID := int64(domainMap["cert_id"].(float64))
	redirect := domainMap["redirect"].(bool)
	location := domainMap["location"].(string)
	pCert, _ := SysCallGetCertByID(certID)
	domain := GetDomainByID(domainID)
	if domainID == 0 {
		// New domain
		newDomainID := data.DAL.InsertDomain(domainName, app.ID, certID, redirect, location)
		domain = new(models.Domain)
		domain.ID = newDomainID
		Domains = append(Domains, domain)
	} else {
		err := data.DAL.UpdateDomain(domainName, app.ID, certID, redirect, location, domain.ID)
		if err != nil {
			utils.DebugPrintln("UpdateDomain", err)
		}
	}
	domain.Name = domainName
	domain.AppID = app.ID
	domain.CertID = certID
	domain.Redirect = redirect
	domain.Location = location
	domain.App = app
	domain.Cert = pCert
	DomainsMap.Store(domainName, models.DomainRelation{App: app, Cert: pCert, Redirect: redirect, Location: location})
	return domain
}

func GetDomainIndex(domain *models.Domain) int {
	for i := 0; i < len(Domains); i++ {
		if Domains[i].ID == domain.ID {
			return i
		}
	}
	return -1
}

func DeleteDomain(domain *models.Domain) {
	i := GetDomainIndex(domain)
	Domains = append(Domains[:i], Domains[i+1:]...)
}

func DeleteDomainsByApp(app *models.Application) {
	for _, domain := range app.Domains {
		DeleteDomain(domain)
		DomainsMap.Delete(domain.Name)
	}
	err := data.DAL.DeleteDomainByAppID(app.ID)
	if err != nil {
		utils.DebugPrintln("DeleteDomainsByAppID", err)
	}
}

func InterfaceContainsDomainID(domains []interface{}, domain_id int64) bool {
	for _, domain := range domains {
		destMap := domain.(map[string]interface{})
		id := int64(destMap["id"].(float64))
		if id == domain_id {
			return true
		}
	}
	return false
}
