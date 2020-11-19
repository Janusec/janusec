/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:22:46
 * @Last Modified: U2, 2018-07-14 16:22:46
 */

package backend

import (
	"janusec/data"
	"janusec/utils"

	_ "github.com/lib/pq"
)

// InitDatabase create if not exists tables
func InitDatabase() {
	dal := data.DAL
	err := dal.CreateTableIfNotExistsCertificates()
	if err != nil {
		utils.DebugPrintln("InitDatabase certificates", err)
	}
	err = dal.CreateTableIfNotExistsApplications()
	if err != nil {
		utils.DebugPrintln("InitDatabase applications", err)
	}
	// 0.9.12 +,  VipApplications
	err = dal.CreateTableIfNotExistsVipApplications()
	if err != nil {
		utils.DebugPrintln("InitDatabase applications", err)
	}
	err = dal.CreateTableIfNotExistsDomains()
	if err != nil {
		utils.DebugPrintln("InitDatabase domains", err)
	}
	err = dal.CreateTableIfNotExistsDestinations()
	if err != nil {
		utils.DebugPrintln("InitDatabase destinations", err)
	}
	err = dal.CreateTableIfNotExistsVipTargets()
	if err != nil {
		utils.DebugPrintln("InitDatabase vip_targets", err)
	}
	err = dal.CreateTableIfNotExistsSettings()
	if err != nil {
		utils.DebugPrintln("InitDatabase settings", err)
	}
	err = dal.CreateTableIfNotExistsAppUsers()
	if err != nil {
		utils.DebugPrintln("InitDatabase appusers", err)
	}
	_, err = dal.InsertIfNotExistsAppUser(`admin`, `1f7d7e9decee9561f457bbc64dd76173ea3e1c6f13f0f55dc1bc4e99e5b8b494`,
		`afa8bae009c9dbf4135f62e165847227`, ``, true, true, true, true)
	if err != nil {
		utils.DebugPrintln("InitDatabase InsertIfNotExistsAppUser", err)
	}
	err = dal.CreateTableIfNotExistsNodes()
	if err != nil {
		utils.DebugPrintln("InitDatabase CreateTableIfNotExistsNodes", err)
	}
	err = dal.CreateTableIfNotExistsTOTP()
	if err != nil {
		utils.DebugPrintln("InitDatabase CreateTableIfNotExistsTOTP", err)
	}
	// Upgrade to latest version
	if dal.ExistColumnInTable("domains", "redirect") == false {
		// v0.9.6+ required
		err = dal.ExecSQL(`alter table domains add column redirect boolean default false, add column location varchar(256) default ''`)
		if err != nil {
			utils.DebugPrintln("InitDatabase alter table domains", err)
		}
	}
	if dal.ExistColumnInTable("applications", "oauth_required") == false {
		// v0.9.7+ required
		err = dal.ExecSQL(`alter table applications add column oauth_required boolean default false, add column session_seconds bigint default 7200, add column owner varchar(128)`)
		if err != nil {
			utils.DebugPrintln("InitDatabase alter table applications oauth", err)
		}
	}
	if dal.ExistColumnInTable("destinations", "route_type") == false {
		// v0.9.8+ required
		err = dal.ExecSQL(`alter table destinations add column route_type bigint default 1, add column request_route varchar(128) default '/', add column backend_route varchar(128) default '/'`)
		if err != nil {
			utils.DebugPrintln("InitDatabase alter table destinations", err)
		}
	}
	if dal.ExistColumnInTable("ccpolicies", "interval_seconds") == true {
		// v0.9.9 interval_seconds, v0.9.10 interval_milliseconds
		err = dal.ExecSQL(`ALTER TABLE ccpolicies RENAME COLUMN interval_seconds TO interval_milliseconds`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE ccpolicies", err)
		}
		err = dal.ExecSQL(`UPDATE ccpolicies SET interval_milliseconds=interval_milliseconds*1000`)
		if err != nil {
			utils.DebugPrintln("InitDatabase UPDATE ccpolicies", err)
		}
	}
	if dal.ExistColumnInTable("applications", "csp") == false {
		// v0.9.11 CSP
		err = dal.ExecSQL(`alter table applications add column csp_enabled boolean default false, add column csp varchar(1024) default 'default-src ''self'''`)
		if err != nil {
			utils.DebugPrintln("InitDatabase alter table applications", err)
		}
	}
	if dal.ExistColumnInTable("totp", "uid") == true {
		// 0.9.12+fix
		err = dal.ExecSQL(`ALTER TABLE totp RENAME COLUMN uid TO totp_uid`)
		if err != nil {
			utils.DebugPrintln("InitDatabase alter table totp", err)
		}
	}
}

func LoadAppConfiguration() {
	LoadCerts()
	LoadApps()
	LoadVipApps()
	if data.IsPrimary {
		LoadDestinations()
		LoadDomains()
		LoadAppDomainNames()
		LoadNodes()
	} else {
		LoadRoute()
		LoadDomains()
	}
}
