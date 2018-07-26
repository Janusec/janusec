/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:22:46
 * @Last Modified: U2, 2018-07-14 16:22:46
 */

package backend

import (
	"github.com/Janusec/janusec/data"
	_ "github.com/lib/pq"
)

func InitDatabase() {
	dal := data.DAL
	dal.CreateTableIfNotExistsCertificates()
	dal.CreateTableIfNotExistsApplications()
	dal.CreateTableIfNotExistsDomains()
	dal.CreateTableIfNotExistsDestinations()
	dal.CreateTableIfNotExistsSettings()
	dal.CreateTableIfNotExistsAppUsers()
	dal.InsertIfNotExistsAppUser(`admin`, `1f7d7e9decee9561f457bbc64dd76173ea3e1c6f13f0f55dc1bc4e99e5b8b494`,
		`afa8bae009c9dbf4135f62e165847227`, ``, true, true, true, true)
	dal.CreateTableIfNotExistsNodes()
}

func LoadAppConfiguration() {
	LoadCerts()
	LoadApps()
	if data.IsMaster {
		LoadDestinations()
		LoadDomains()
		LoadAppDomainNames()
		LoadNodes()
	} else {
		LoadDomains()
	}
}
