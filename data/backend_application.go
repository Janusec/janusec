/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:07
 * @Last Modified: U2, 2018-07-14 16:24:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsApplications ...
func (dal *MyDAL) CreateTableIfNotExistsApplications() error {
	const sqlCreateTableIfNotExistsApplications = `CREATE TABLE IF NOT EXISTS "applications"("id" bigserial PRIMARY KEY,"name" VARCHAR(128) NOT NULL,"internal_scheme" VARCHAR(8) NOT NULL,"redirect_https" boolean,"hsts_enabled" boolean,"waf_enabled" boolean,"shield_enabled" boolean,"ip_method" bigint,"description" VARCHAR(256) NOT NULL,"oauth_required" boolean,"session_seconds" bigint default 7200,"owner" VARCHAR(128) NOT NULL,"csp_enabled" boolean default false,"csp" VARCHAR(1024) NOT NULL DEFAULT 'default-src ''self''',"cache_enabled" boolean default true,"custom_headers" VARCHAR(1024) DEFAULT '')`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsApplications)
	return err
}

// SelectApplications ...
func (dal *MyDAL) SelectApplications() []*models.DBApplication {
	const sqlSelectApplications = `SELECT "id","name","internal_scheme","redirect_https","hsts_enabled","waf_enabled","shield_enabled","ip_method","description","oauth_required","session_seconds","owner","csp_enabled","csp","cache_enabled","custom_headers","cookie_mgmt_enabled","concise_notice","necessary_notice","functional_notice","enable_functional","analytics_notice","enable_analytics","marketing_notice","enable_marketing","unclassified_notice","enable_unclassified" FROM "applications"`
	rows, err := dal.db.Query(sqlSelectApplications)
	if err != nil {
		utils.DebugPrintln("SelectApplications", err)
		return []*models.DBApplication{}
	}
	defer rows.Close()
	var dbApps []*models.DBApplication
	for rows.Next() {
		dbApp := &models.DBApplication{}
		err = rows.Scan(
			&dbApp.ID,
			&dbApp.Name,
			&dbApp.InternalScheme,
			&dbApp.RedirectHTTPS,
			&dbApp.HSTSEnabled,
			&dbApp.WAFEnabled,
			&dbApp.ShieldEnabled,
			&dbApp.ClientIPMethod,
			&dbApp.Description,
			&dbApp.OAuthRequired,
			&dbApp.SessionSeconds,
			&dbApp.Owner,
			&dbApp.CSPEnabled,
			&dbApp.CSP,
			&dbApp.CacheEnabled,
			&dbApp.CustomHeaders,
			&dbApp.CookieMgmtEnabled,
			&dbApp.ConciseNotice,
			&dbApp.NecessaryNotice,
			&dbApp.FunctionalNotice,
			&dbApp.EnableFunctional,
			&dbApp.AnalyticsNotice,
			&dbApp.EnableAnalytics,
			&dbApp.MarketingNotice,
			&dbApp.EnableMarketing,
			&dbApp.UnclassifiedNotice,
			&dbApp.EnableUnclassified,
		)
		if err != nil {
			utils.DebugPrintln("SelectApplications rows.Scan", err)
		}
		dbApps = append(dbApps, dbApp)
	}
	return dbApps
}

// InsertApplication insert an Application to DB
func (dal *MyDAL) InsertApplication(appName string, internalScheme string, redirectHTTPS bool, hstsEnabled bool, wafEnabled bool, shieldEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string, cspEnabled bool, csp string, cacheEnabled bool, customHeaders string, cookieMgmtEnabled bool, conciseNotice string, necessaryNotice string, functionalNotice string, enableFunctional bool, analyticsNotice string, enableAnalytics bool, marketingNotice string, enableMarketing bool, unclassifiedNotice string, enableUnclassified bool) (newID int64) {
	const sqlInsertApplication = `INSERT INTO "applications"("id","name","internal_scheme","redirect_https","hsts_enabled","waf_enabled","shield_enabled","ip_method","description","oauth_required","session_seconds","owner","csp_enabled","csp","cache_enabled","custom_headers","cookie_mgmt_enabled","concise_notice","necessary_notice","functional_notice","enable_functional","analytics_notice","enable_analytics","marketing_notice","enable_marketing","unclassified_notice","enable_unclassified") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27) RETURNING "id"`
	id := utils.GenSnowflakeID()
	err := dal.db.QueryRow(sqlInsertApplication, id, appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, shieldEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp, cacheEnabled, customHeaders, cookieMgmtEnabled, conciseNotice, necessaryNotice, functionalNotice, enableFunctional, analyticsNotice, enableAnalytics, marketingNotice, enableMarketing, unclassifiedNotice, enableUnclassified).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertApplication", err)
	}
	return newID
}

// UpdateApplication update an Application
func (dal *MyDAL) UpdateApplication(appName string, internalScheme string, redirectHTTPS bool, hstsEnabled bool, wafEnabled bool, shieldEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string, cspEnabled bool, csp string, cacheEnabled bool, customHeaders string, cookieMgmtEnabled bool, conciseNotice string, necessaryNotice string, functionalNotice string, enableFunctional bool, analyticsNotice string, enableAnalytics bool, marketingNotice string, enableMarketing bool, unclassifiedNotice string, enableUnclassified bool, appID int64) error {
	const sqlUpdateApplication = `UPDATE "applications" SET "name"=$1,"internal_scheme"=$2,"redirect_https"=$3,"hsts_enabled"=$4,"waf_enabled"=$5,"shield_enabled"=$6,"ip_method"=$7,"description"=$8,"oauth_required"=$9,"session_seconds"=$10,"owner"=$11,"csp_enabled"=$12,"csp"=$13,"cache_enabled"=$14,"custom_headers"=$15,"cookie_mgmt_enabled"=$16,"concise_notice"=$17,"necessary_notice"=$18,"functional_notice"=$19,"enable_functional"=$20,"analytics_notice"=$21,"enable_analytics"=$22,"marketing_notice"=$23,"enable_marketing"=$24,"unclassified_notice"=$25,"enable_unclassified"=$26 WHERE "id"=$27`
	stmt, _ := dal.db.Prepare(sqlUpdateApplication)
	defer stmt.Close()
	_, err := stmt.Exec(appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, shieldEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp, cacheEnabled, customHeaders, cookieMgmtEnabled, conciseNotice, necessaryNotice, functionalNotice, enableFunctional, analyticsNotice, enableAnalytics, marketingNotice, enableMarketing, unclassifiedNotice, enableUnclassified, appID)
	if err != nil {
		utils.DebugPrintln("UpdateApplication", err)
	}
	return err
}

// DeleteApplication delete an Application
func (dal *MyDAL) DeleteApplication(appID int64) error {
	const sqlDeleteApplication = `DELETE FROM "applications" WHERE "id"=$1`
	stmt, _ := dal.db.Prepare(sqlDeleteApplication)
	defer stmt.Close()
	_, err := stmt.Exec(appID)
	if err != nil {
		utils.DebugPrintln("DeleteApplication", err)
	}
	return err
}
