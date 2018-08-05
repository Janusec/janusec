/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:42
 * @Last Modified: U2, 2018-07-14 16:24:42
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

const (
	sqlCreateTableIfNotExistsDomains = `CREATE TABLE IF NOT EXISTS domains(id bigserial PRIMARY KEY, name varchar(256) NOT NULL, app_id bigint NOT NULL, cert_id bigint)`
	sqlSelectDomainsCountByCertID    = `SELECT COUNT(1) FROM domains WHERE cert_id=$1`
	sqlSelectDomains                 = `SELECT id, name, app_id, cert_id FROM domains`
	sqlInsertDomain                  = `INSERT INTO domains(name,app_id,cert_id) VALUES($1,$2,$3) RETURNING id`
	sqlUpdateDomain                  = `UPDATE domains SET name=$1,app_id=$2,cert_id=$3 WHERE id=$4`
	sqlDeleteDomainByDomainID        = `DELETE FROM domains WHERE id=$1`
	sqlDeleteDomainByAppID           = `DELETE FROM domains WHERE app_id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistsDomains() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDomains)
	return err
}

func (dal *MyDAL) SelectDomains() (dbDomains []*models.DBDomain) {
	rows, err := dal.db.Query(sqlSelectDomains)
	utils.CheckError("SelectDomains", err)
	defer rows.Close()
	for rows.Next() {
		dbDomain := new(models.DBDomain)
		err = rows.Scan(&dbDomain.ID, &dbDomain.Name, &dbDomain.AppID, &dbDomain.CertID)
		dbDomains = append(dbDomains, dbDomain)
	}
	return dbDomains
}

func (dal *MyDAL) SelectDomainsCountByCertID(certID int64) int64 {
	var certDomainsCount int64
	err := dal.db.QueryRow(sqlSelectDomainsCountByCertID, certID).Scan(&certDomainsCount)
	utils.CheckError("SelectDomainsCountByCertID", err)
	return certDomainsCount
}

func (dal *MyDAL) InsertDomain(name string, appID int64, certID int64) (newID int64) {
	err := dal.db.QueryRow(sqlInsertDomain, name, appID, certID).Scan(&newID)
	utils.CheckError("InsertDomain", err)
	return newID
}

func (dal *MyDAL) UpdateDomain(name string, appID int64, certID int64, domainID int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateDomain)
	defer stmt.Close()
	_, err = stmt.Exec(name, appID, certID, domainID)
	utils.CheckError("UpdateDomain", err)
	return err
}

func (dal *MyDAL) DeleteDomainByDomainID(domainID int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDomainByDomainID)
	defer stmt.Close()
	_, err = stmt.Exec(domainID)
	utils.CheckError("DeleteDomainByDomainID", err)
	return err
}

func (dal *MyDAL) DeleteDomainByAppID(appID int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDomainByAppID)
	defer stmt.Close()
	_, err = stmt.Exec(appID)
	utils.CheckError("DeleteDomainByAppID", err)
	return err
}
