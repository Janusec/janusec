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

	// PostgreSQL
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
	if !dal.ExistColumnInTable("domains", "redirect") {
		// v0.9.6+ required
		err = dal.ExecSQL(`ALTER TABLE "domains" ADD COLUMN "redirect" boolean default false, ADD COLUMN "location" VARCHAR(256) NOT NULL DEFAULT ''`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE domains", err)
		}
	}
	if !dal.ExistColumnInTable("applications", "oauth_required") {
		// v0.9.7+ required
		err = dal.ExecSQL(`ALTER TABLE "applications" ADD COLUMN "oauth_required" boolean default false, ADD COLUMN "session_seconds" bigint default 7200, ADD COLUMN "owner" VARCHAR(128)`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE applications oauth", err)
		}
	}
	if !dal.ExistColumnInTable("destinations", "route_type") {
		// v0.9.8+ required
		err = dal.ExecSQL(`ALTER TABLE "destinations" ADD COLUMN "route_type" bigint default 1, ADD COLUMN "request_route" VARCHAR(128) NOT NULL DEFAULT '/', ADD COLUMN "backend_route" VARCHAR(128) NOT NULL DEFAULT '/'`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE destinations", err)
		}
	}
	if dal.ExistColumnInTable("ccpolicies", "interval_seconds") {
		// v0.9.9 interval_seconds, v0.9.10 interval_milliseconds
		err = dal.ExecSQL(`ALTER TABLE "ccpolicies" RENAME COLUMN "interval_seconds" TO "interval_milliseconds"`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE ccpolicies", err)
		}
		err = dal.ExecSQL(`UPDATE "ccpolicies" SET "interval_milliseconds"="interval_milliseconds"*1000`)
		if err != nil {
			utils.DebugPrintln("InitDatabase UPDATE ccpolicies", err)
		}
	}
	if !dal.ExistColumnInTable("applications", "csp") {
		// v0.9.11 CSP
		err = dal.ExecSQL(`ALTER TABLE "applications" ADD COLUMN "csp_enabled" boolean default false, ADD COLUMN "csp" VARCHAR(1024) NOT NULL DEFAULT 'default-src ''self'''`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE applications", err)
		}
	}
	if dal.ExistColumnInTable("totp", "uid") {
		// 0.9.12+fix
		err = dal.ExecSQL(`ALTER TABLE "totp" RENAME COLUMN "uid" TO "totp_uid"`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE totp", err)
		}
	}
	// 0.9.13 alter column ccpolicies type
	_ = dal.ExecSQL(`ALTER TABLE "ccpolicies" ALTER COLUMN "interval_milliseconds" TYPE double precision`)
	//if err != nil {
	//utils.DebugPrintln("InitDatabase ALTER TABLE ccpolicies ALTER COLUMN interval_milliseconds", err)
	//}
	// 0.9.13 alter column block_seconds type
	_ = dal.ExecSQL(`ALTER TABLE "ccpolicies" ALTER COLUMN "block_seconds" TYPE double precision`)
	//if err != nil {
	//utils.DebugPrintln("InitDatabase ALTER TABLE ccpolicies ALTER COLUMN block_seconds", err)
	//}

	// v1.2.0 add shield_enabled to application
	if !dal.ExistColumnInTable("applications", "shield_enabled") {
		// v1.2.0+ required
		err = dal.ExecSQL(`ALTER TABLE "applications" ADD COLUMN "shield_enabled" boolean default false`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE applications add shield_enabled", err)
		}
	}

	// v1.2.4 add constraint to access_stats
	if !dal.ExistConstraint("access_stats", "stat_id") {
		_ = dal.ExecSQL(`ALTER TABLE "access_stats" ADD CONSTRAINT "stat_id" unique ("app_id","url_path","stat_date")`)
		//if err != nil {
		//utils.DebugPrintln("InitDatabase ALTER TABLE access_stats add constraint", err)
		//}
	}

	if !dal.ExistColumnInTable("applications", "cache_enabled") {
		// v1.2.5+ required
		err = dal.ExecSQL(`ALTER TABLE "applications" ADD COLUMN "cache_enabled" boolean default true`)
		if err != nil {
			utils.DebugPrintln("InitDatabase ALTER TABLE applications add cache_enabled", err)
		}
	}
}

// LoadAppConfiguration ...
func LoadAppConfiguration() {
	utils.DebugPrintln("LoadAppConfiguration")
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
