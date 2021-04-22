/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:42
 * @Last Modified: U2, 2018-07-14 16:24:42
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsDomains = `CREATE TABLE IF NOT EXISTS "domains"("id" bigserial PRIMARY KEY, "name" VARCHAR(256) NOT NULL, "app_id" bigint NOT NULL, "cert_id" bigint, "redirect" boolean, "location" VARCHAR(256))`
	sqlSelectDomainsCountByCertID    = `SELECT COUNT(1) FROM "domains" WHERE "cert_id"=$1`
	sqlSelectDomains                 = `SELECT "id", "name", "app_id", "cert_id", "redirect", "location" FROM "domains"`
	sqlInsertDomain                  = `INSERT INTO "domains"("name", "app_id", "cert_id", "redirect", "location") VALUES($1,$2,$3,$4,$5) RETURNING "id"`
	sqlUpdateDomain                  = `UPDATE "domains" SET "name"=$1,"app_id"=$2,"cert_id"=$3,"redirect"=$4,"location"=$5 WHERE "id"=$6`
	sqlDeleteDomainByDomainID        = `DELETE FROM "domains" WHERE "id"=$1`
	sqlDeleteDomainByAppID           = `DELETE FROM "domains" WHERE "app_id"=$1`
)

// CreateTableIfNotExistsDomains ...
func (dal *MyDAL) CreateTableIfNotExistsDomains() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDomains)
	return err
}

// SelectDomains ...
func (dal *MyDAL) SelectDomains() []*models.DBDomain {
	rows, err := dal.db.Query(sqlSelectDomains)
	utils.CheckError("SelectDomains", err)
	defer rows.Close()
	dbDomains := []*models.DBDomain{}
	for rows.Next() {
		dbDomain := &models.DBDomain{}
		_ = rows.Scan(&dbDomain.ID, &dbDomain.Name, &dbDomain.AppID, &dbDomain.CertID, &dbDomain.Redirect, &dbDomain.Location)
		dbDomains = append(dbDomains, dbDomain)
	}
	return dbDomains
}

// SelectDomainsCountByCertID ...
func (dal *MyDAL) SelectDomainsCountByCertID(certID int64) int64 {
	var certDomainsCount int64
	err := dal.db.QueryRow(sqlSelectDomainsCountByCertID, certID).Scan(&certDomainsCount)
	utils.CheckError("SelectDomainsCountByCertID", err)
	return certDomainsCount
}

// InsertDomain ...
func (dal *MyDAL) InsertDomain(name string, appID int64, certID int64, redirect bool, location string) (newID int64) {
	err := dal.db.QueryRow(sqlInsertDomain, name, appID, certID, redirect, location).Scan(&newID)
	utils.CheckError("InsertDomain", err)
	return newID
}

// UpdateDomain ...
func (dal *MyDAL) UpdateDomain(name string, appID int64, certID int64, redirect bool, location string, domainID int64) error {
	_, err := dal.db.Exec(sqlUpdateDomain, name, appID, certID, redirect, location, domainID)
	utils.CheckError("UpdateDomain", err)
	return err
}

// DeleteDomainByDomainID ...
func (dal *MyDAL) DeleteDomainByDomainID(domainID int64) error {
	stmt, _ := dal.db.Prepare(sqlDeleteDomainByDomainID)
	defer stmt.Close()
	_, err := stmt.Exec(domainID)
	utils.CheckError("DeleteDomainByDomainID", err)
	return err
}

// DeleteDomainByAppID ...
func (dal *MyDAL) DeleteDomainByAppID(appID int64) error {
	stmt, _ := dal.db.Prepare(sqlDeleteDomainByAppID)
	defer stmt.Close()
	_, err := stmt.Exec(appID)
	utils.CheckError("DeleteDomainByAppID", err)
	return err
}
