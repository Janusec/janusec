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
	dal.CreateTableIfNotExistsTOTP()
	// Upgrade to latest version
	if dal.ExistColumnInTable("domains", "redirect") == false {
		// v0.9.6+ required
		dal.ExecSQL(`alter table domains add column redirect boolean default false, add column location varchar(256) default null`)
	}
	if dal.ExistColumnInTable("applications", "oauth_required") == false {
		// v0.9.7+ required
		dal.ExecSQL(`alter table applications add column oauth_required boolean default false, add column session_seconds bigint default 7200, add column owner varchar(128)`)
	}
	if dal.ExistColumnInTable("destinations", "route_type") == false {
		// v0.9.8+ required
		dal.ExecSQL(`alter table destinations add column route_type bigint default 1, add column request_route varchar(128) default '/', add column backend_route varchar(128) default '/'`)
	}
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
		LoadRoute()
		LoadDomains()
	}
}
