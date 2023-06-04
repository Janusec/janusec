/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 18:54
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsDNSDomains ...
func (dal *MyDAL) CreateTableIfNotExistsDNSDomains() error {
	const sqlCreateTableIfNotExistsDNSDomains = `CREATE TABLE IF NOT EXISTS "dns_domains"("id" BIGINT PRIMARY KEY, "name" VARCHAR(256) NOT NULL)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDNSDomains)
	return err
}

// SelectDNSDomains ...
func (dal *MyDAL) SelectDNSDomains() []*models.DNSDomain {
	const sqlSelectDNSDomains = `SELECT "id","name" FROM "dns_domains"`
	rows, err := dal.db.Query(sqlSelectDNSDomains)
	if err != nil {
		utils.DebugPrintln("SelectDNSDomains", err)
	}
	defer rows.Close()
	dnsDomains := []*models.DNSDomain{}
	for rows.Next() {
		dnsDomain := &models.DNSDomain{}
		_ = rows.Scan(&dnsDomain.ID, &dnsDomain.Name)
		dnsDomains = append(dnsDomains, dnsDomain)
	}
	return dnsDomains
}

func (dal *MyDAL) InsertDNSDomain(dnsDomain *models.DNSDomain) error {
	const sqlInsertDNSDomain = `INSERT INTO "dns_domains"("id","name") VALUES($1,$2)`
	_, err := dal.db.Exec(sqlInsertDNSDomain, dnsDomain.ID, dnsDomain.Name)
	return err
}

func (dal *MyDAL) UpdateDNSDomain(dnsDomain *models.DNSDomain) error {
	const sqlUpdateDNSDomain = `UPDATE "dns_domains" SET "name"=$1 WHERE "id"=$2`
	_, err := dal.db.Exec(sqlUpdateDNSDomain, dnsDomain.Name, dnsDomain.ID)
	return err
}

func (dal *MyDAL) DeleteDNSDomainByID(id int64) error {
	const sqlDelDNSDomain = `DELETE FROM "dns_domains" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDelDNSDomain, id)
	return err
}

/*
func (dal *MyDAL) SelectDNSDomainByID(id int64) (*models.DNSDomain, error) {
	dnsDomain := models.DNSDomain{
		ID: id,
	}
	const sqlSelectDNSDomains = `SELECT "name" FROM "dns_domains" WHERE "id"=$1`
	err := dal.db.QueryRow(sqlSelectDNSDomains, id).Scan(&dnsDomain.Name)
	return &dnsDomain, err
}
*/
