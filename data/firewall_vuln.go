/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:14
 * @Last Modified: U2, 2018-07-14 16:31:14
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsVulnType = `CREATE TABLE IF NOT EXISTS "vulntypes"("id" bigint primary key,"name" VARCHAR(128))`
	sqlExistsVulnType                 = `SELECT COALESCE((SELECT 1 FROM "vulntypes" LIMIT 1),0)`
	sqlInsertVulnType                 = `INSERT INTO "vulntypes"("id","name") VALUES($1,$2)`
	sqlSelectVulnTypes                = `SELECT "id","name" FROM "vulntypes"`
)

// CreateTableIfNotExistsVulnType ...
func (dal *MyDAL) CreateTableIfNotExistsVulnType() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVulnType)
	return err
}

// ExistsVulnType ...
func (dal *MyDAL) ExistsVulnType() bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsVulnType).Scan(&exist)
	if err != nil {
		utils.DebugPrintln("ExistsVulnType", err)
	}
	return exist != 0
}

// SelectVulnTypes ...
func (dal *MyDAL) SelectVulnTypes() ([]*models.VulnType, error) {
	vulnTypes := []*models.VulnType{}
	rows, err := dal.db.Query(sqlSelectVulnTypes)
	if err != nil {
		utils.DebugPrintln("SelectVulnTypes", err)
	}
	defer rows.Close()
	for rows.Next() {
		vulnType := &models.VulnType{}
		err = rows.Scan(&vulnType.ID, &vulnType.Name)
		if err != nil {

			utils.DebugPrintln("SelectVulnTypes rows.Scan", err)
			return vulnTypes, err
		}
		vulnTypes = append(vulnTypes, vulnType)
	}
	return vulnTypes, err
}

// InsertVulnType ...
func (dal *MyDAL) InsertVulnType(id int64, name string) (err error) {
	_, err = dal.db.Exec(sqlInsertVulnType, id, name)
	if err != nil {
		utils.DebugPrintln("InsertVulnType", err)
	}
	return err
}
