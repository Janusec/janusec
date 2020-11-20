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

func (dal *MyDAL) CreateTableIfNotExistsApplications() error {
	const sqlCreateTableIfNotExistsApplications = `CREATE TABLE IF NOT EXISTS "applications"("id" bigserial PRIMARY KEY,"name" VARCHAR(128) NOT NULL,"internal_scheme" VARCHAR(8) NOT NULL,"redirect_https" boolean,"hsts_enabled" boolean,"waf_enabled" boolean,"ip_method" bigint,"description" VARCHAR(256) NOT NULL,"oauth_required" boolean,"session_seconds" bigint default 7200,"owner" VARCHAR(128) NOT NULL,"csp_enabled" boolean default false,"csp" VARCHAR(1024) NOT NULL DEFAULT 'default-src ''self''')`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsApplications)
	return err
}

func (dal *MyDAL) SelectApplications() []*models.DBApplication {
	const sqlSelectApplications = `SELECT "id","name","internal_scheme","redirect_https","hsts_enabled","waf_enabled","ip_method","description","oauth_required","session_seconds","owner","csp_enabled","csp" FROM "applications"`
	rows, err := dal.db.Query(sqlSelectApplications)
	utils.CheckError("SelectApplications", err)
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
			&dbApp.ClientIPMethod,
			&dbApp.Description,
			&dbApp.OAuthRequired,
			&dbApp.SessionSeconds,
			&dbApp.Owner,
			&dbApp.CSPEnabled,
			&dbApp.CSP)
		if err != nil {
			utils.DebugPrintln("SelectApplications rows.Scan", err)
		}
		dbApps = append(dbApps, dbApp)
	}
	return dbApps
}

// InsertApplication insert an Application to DB
func (dal *MyDAL) InsertApplication(appName string, internalScheme string, redirectHTTPS bool, hstsEnabled bool, wafEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string, cspEnabled bool, csp string) (newID int64) {
	const sqlInsertApplication = `INSERT INTO "applications"("name","internal_scheme","redirect_https","hsts_enabled","waf_enabled","ip_method","description","oauth_required","session_seconds","owner","csp_enabled","csp") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING "id"`
	err := dal.db.QueryRow(sqlInsertApplication, appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp).Scan(&newID)
	utils.CheckError("InsertApplication", err)
	return newID
}

// UpdateApplication update an Application
func (dal *MyDAL) UpdateApplication(appName string, internalScheme string, redirectHTTPS bool, hstsEnabled bool, wafEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string, cspEnabled bool, csp string, appID int64) error {
	const sqlUpdateApplication = `UPDATE "applications" SET "name"=$1,"internal_scheme"=$2,"redirect_https"=$3,"hsts_enabled"=$4,"waf_enabled"=$5,"ip_method"=$6,"description"=$7,"oauth_required"=$8,"session_seconds"=$9,"owner"=$10,"csp_enabled"=$11,"csp"=$12 WHERE "id"=$13`
	stmt, err := dal.db.Prepare(sqlUpdateApplication)
	defer stmt.Close()
	_, err = stmt.Exec(appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp, appID)
	utils.CheckError("UpdateApplication", err)
	return err
}

// DeleteApplication delete an Application
func (dal *MyDAL) DeleteApplication(appID int64) error {
	const sqlDeleteApplication = `DELETE FROM "applications" WHERE "id"=$1`
	stmt, err := dal.db.Prepare(sqlDeleteApplication)
	defer stmt.Close()
	_, err = stmt.Exec(appID)
	utils.CheckError("DeleteApplication", err)
	return err
}
