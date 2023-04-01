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
	// Domains for all domains
	Domains = []*models.Domain{}

	// DomainsMap (string, models.DomainRelation)
	DomainsMap = sync.Map{}
)

// LoadDomains ...
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

// GetDomainByID ...
func GetDomainByID(id int64) *models.Domain {
	for _, domain := range Domains {
		if domain.ID == id {
			return domain
		}
	}
	return nil
}

// GetDomainByName ...
func GetDomainByName(domainName string) *models.Domain {
	for _, domain := range Domains {
		if domain.Name == domainName {
			return domain
		}
	}
	return nil
}

// UpdateDomain ...
func UpdateDomain(app *models.Application, newDomain *models.Domain) *models.Domain {
	if newDomain.ID == 0 {
		// New domain
		newDomain.ID = data.DAL.InsertDomain(newDomain.Name, app.ID, newDomain.CertID, newDomain.Redirect, newDomain.Location)
		Domains = append(Domains, newDomain)
	} else {
		oldDomain := GetDomainByID(newDomain.ID)
		err := data.DAL.UpdateDomain(newDomain.Name, app.ID, newDomain.CertID, newDomain.Redirect, newDomain.Location, oldDomain.ID)
		if err != nil {
			utils.DebugPrintln("UpdateDomain", err)
		}
		oldDomain = newDomain
	}
	newDomain.AppID = app.ID
	newDomain.App = app
	pCert, _ := SysCallGetCertByID(newDomain.CertID)
	newDomain.Cert = pCert
	DomainsMap.Store(newDomain.Name, models.DomainRelation{App: app, Cert: pCert, Redirect: newDomain.Redirect, Location: newDomain.Location})
	return newDomain
}

// GetDomainIndex ...
func GetDomainIndex(domain *models.Domain) int {
	for i := 0; i < len(Domains); i++ {
		if Domains[i].ID == domain.ID {
			return i
		}
	}
	return -1
}

// DeleteDomain ...
func DeleteDomain(domain *models.Domain) {
	i := GetDomainIndex(domain)
	Domains = append(Domains[:i], Domains[i+1:]...)
}

// DeleteDomainsByApp ...
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

// ContainsDomainID ...
func ContainsDomainID(domains []*models.Domain, domainID int64) bool {
	for _, domain := range domains {
		if domain.ID == domainID {
			return true
		}
	}
	return false
}
