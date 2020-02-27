/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:22:10
 * @Last Modified: U2, 2018-07-14 16:22:10
 */

package backend

import (
	"sync"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
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
	if data.IsMaster {
		dbDomains = data.DAL.SelectDomains()
	} else {
		dbDomains = RPCSelectDomains()
	}
	for _, dbDomain := range dbDomains {
		pApp, _ := GetApplicationByID(dbDomain.AppID)
		pCert, _ := GetCertificateByID(dbDomain.CertID)
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

/*
func IsStaticDir(domain string, path string) (bool) {
    if strings.Contains(path, "?") {
        return false
    }
    app := DomainsMap[domain].App
    static_dirs := app.StaticDirs
    for _, static_dir := range static_dirs {
        if strings.HasPrefix(path, static_dir) {
            local_static_file := "./user_static_files/" + strconv.Itoa(app.ID) + path
            fmt.Println("local_static_file:", local_static_file)
            if _, err := os.Stat(local_static_file); os.IsNotExist(err) {
                fmt.Println("FileNotExist:", local_static_file)
                dest := app.SelectDestination()
                target_url := app.InternalScheme + "://" + dest + path
                req, err := http.NewRequest("GET", target_url, nil)
                utils.CheckError(err)
                req.Host = domain
                client := &http.Client{}
                resp, err := client.Do(req)
                utils.CheckError(err)
                defer resp.Body.Close()
                utils.CheckError(err)
                path_all := utils.GetDirAll(local_static_file)
                fmt.Println("path_all:", path_all)
                err = os.MkdirAll(path_all, 0777)
                utils.CheckError(err)
                f, err := os.Create(local_static_file)
                utils.CheckError(err)
                size, err := io.Copy(f, resp.Body)
                utils.CheckError(err)
                fmt.Println("CDN Copy:", target_url, size)
            }
            return true
        }
    }
    return false
}
*/

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
	pCert, _ := GetCertificateByID(certID)
	domain := GetDomainByID(domainID)
	if domainID == 0 {
		// New domain
		newDomainID := data.DAL.InsertDomain(domainName, app.ID, certID, redirect, location)
		domain = new(models.Domain)
		domain.ID = newDomainID
		Domains = append(Domains, domain)
	} else {
		data.DAL.UpdateDomain(domainName, app.ID, certID, redirect, location, domain.ID)
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
	//fmt.Println("DeleteDomain Domains", Domains)
	//fmt.Println("DeleteDomain i=", i)
	Domains = append(Domains[:i], Domains[i+1:]...)
}

func DeleteDomainsByApp(app *models.Application) {
	for _, domain := range app.Domains {
		DeleteDomain(domain)
		//delete(DomainsMap, domain.Name)
		DomainsMap.Delete(domain.Name)
	}
	data.DAL.DeleteDomainByAppID(app.ID)
	/*
	   _,err := DB.Exec("DELETE FROM domains where app_id=$1",app.ID)
	   utils.CheckError(err)
	*/
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
