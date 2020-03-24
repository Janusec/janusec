/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:07
 * @Last Modified: U2, 2018-07-14 16:24:07
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func (dal *MyDAL) CreateTableIfNotExistsApplications() error {
	const sqlCreateTableIfNotExistsApplications = `CREATE TABLE IF NOT EXISTS applications(id bigserial PRIMARY KEY,name varchar(128) NOT NULL,internal_scheme varchar(8) NOT NULL,redirect_https boolean,hsts_enabled boolean,waf_enabled boolean,ip_method bigint,description varchar(256),oauth_required boolean,session_seconds bigint default 7200,owner varchar(128))`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsApplications)
	return err
}

func (dal *MyDAL) SelectApplications() []*models.DBApplication {
	const sqlSelectApplications = `SELECT id,name,internal_scheme,redirect_https,hsts_enabled,waf_enabled,ip_method,description,oauth_required,session_seconds,owner FROM applications`
	rows, err := dal.db.Query(sqlSelectApplications)
	utils.CheckError("SelectApplications", err)
	defer rows.Close()
	var dbApps []*models.DBApplication
	for rows.Next() {
		dbApp := new(models.DBApplication)
		rows.Scan(
			&dbApp.ID,
			&dbApp.Name,
			&dbApp.InternalScheme,
			&dbApp.RedirectHttps,
			&dbApp.HSTSEnabled,
			&dbApp.WAFEnabled,
			&dbApp.ClientIPMethod,
			&dbApp.Description,
			&dbApp.OAuthRequired,
			&dbApp.SessionSeconds,
			&dbApp.Owner)
		dbApps = append(dbApps, dbApp)
	}
	return dbApps
}

func (dal *MyDAL) InsertApplication(appName string, internalScheme string, redirectHttps bool, hstsEnabled bool, wafEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string) (newID int64) {
	const sqlInsertApplication = `INSERT INTO applications(name,internal_scheme,redirect_https,hsts_enabled,waf_enabled,ip_method,description,oauth_required,session_seconds,owner) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`
	err := dal.db.QueryRow(sqlInsertApplication, appName, internalScheme, redirectHttps, hstsEnabled, wafEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner).Scan(&newID)
	utils.CheckError("InsertApplication", err)
	return newID
}

func (dal *MyDAL) UpdateApplication(appName string, internalScheme string, redirectHttps bool, hstsEnabled bool, wafEnabled bool, ipMethod models.IPMethod, description string, oauthRequired bool, sessionSeconds int64, owner string, appID int64) error {
	const sqlUpdateApplication = `UPDATE applications SET name=$1,internal_scheme=$2,redirect_https=$3,hsts_enabled=$4,waf_enabled=$5,ip_method=$6,description=$7,oauth_required=$8,session_seconds=$9,owner=$10 WHERE id=$11`
	stmt, err := dal.db.Prepare(sqlUpdateApplication)
	defer stmt.Close()
	_, err = stmt.Exec(appName, internalScheme, redirectHttps, hstsEnabled, wafEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, appID)
	utils.CheckError("UpdateApplication", err)
	return err
}

func (dal *MyDAL) DeleteApplication(app_id int64) error {
	const sqlDeleteApplication = `DELETE FROM applications WHERE id=$1`
	stmt, err := dal.db.Prepare(sqlDeleteApplication)
	defer stmt.Close()
	_, err = stmt.Exec(app_id)
	utils.CheckError("DeleteApplication", err)
	return err
}
