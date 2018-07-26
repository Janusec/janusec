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

func (dal *MyDAL) SelectDomains() (db_domains []*models.DBDomain) {
	rows, err := dal.db.Query(sqlSelectDomains)
	utils.CheckError("SelectDomains", err)
	defer rows.Close()
	for rows.Next() {
		db_domain := new(models.DBDomain)
		err = rows.Scan(&db_domain.ID, &db_domain.Name, &db_domain.AppID, &db_domain.CertID)
		db_domains = append(db_domains, db_domain)
	}
	return db_domains
}

func (dal *MyDAL) SelectDomainsCountByCertID(cert_id int64) int64 {
	var cert_domains_count int64
	err := dal.db.QueryRow(sqlSelectDomainsCountByCertID, cert_id).Scan(&cert_domains_count)
	utils.CheckError("SelectDomainsCountByCertID", err)
	return cert_domains_count
}

func (dal *MyDAL) InsertDomain(name string, app_id int64, cert_id int64) (new_id int64) {
	err := dal.db.QueryRow(sqlInsertDomain, name, app_id, cert_id).Scan(&new_id)
	utils.CheckError("InsertDomain", err)
	return new_id
}

func (dal *MyDAL) UpdateDomain(name string, app_id int64, cert_id int64, domain_id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateDomain)
	defer stmt.Close()
	_, err = stmt.Exec(name, app_id, cert_id, domain_id)
	utils.CheckError("UpdateDomain", err)
	return err
}

func (dal *MyDAL) DeleteDomainByDomainID(domain_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDomainByDomainID)
	defer stmt.Close()
	_, err = stmt.Exec(domain_id)
	utils.CheckError("DeleteDomainByDomainID", err)
	return err
}

func (dal *MyDAL) DeleteDomainByAppID(app_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDomainByAppID)
	defer stmt.Close()
	_, err = stmt.Exec(app_id)
	utils.CheckError("DeleteDomainByAppID", err)
	return err
}
