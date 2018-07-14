/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:14
 * @Last Modified: U2, 2018-07-14 16:31:14
 */

package data

import (
	"../models"
	"../utils"
)

const (
	sqlCreateTableIfNotExistsVulnType = `CREATE TABLE IF NOT EXISTS vulntypes(id bigint primary key,name varchar(128))`
	sqlExistsVulnType                 = `SELECT coalesce((SELECT 1 FROM vulntypes LIMIT 1),0)`
	sqlInsertVulnType                 = `INSERT INTO vulntypes(id,name) values($1,$2)`
	sqlSelectVulnTypes                = `SELECT id,name FROM vulntypes`
)

func (dal *MyDAL) CreateTableIfNotExistsVulnType() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVulnType)
	return err
}

func (dal *MyDAL) ExistsVulnType() bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsVulnType).Scan(&exist)
	utils.CheckError("ExistsVulnType", err)
	if exist == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) SelectVulnTypes() (vuln_types []*models.VulnType, err error) {
	rows, err := dal.db.Query(sqlSelectVulnTypes)
	utils.CheckError("SelectVulnTypes", err)
	defer rows.Close()
	for rows.Next() {
		vuln_type := new(models.VulnType)
		err = rows.Scan(&vuln_type.ID, &vuln_type.Name)
		utils.CheckError("SelectVulnTypes rows.Scan", err)
		if err != nil {
			return vuln_types, err
		}
		vuln_types = append(vuln_types, vuln_type)
	}
	return vuln_types, err
}

func (dal *MyDAL) InsertVulnType(id int64, name string) (err error) {
	_, err = dal.db.Exec(sqlInsertVulnType, id, name)
	utils.CheckError("InsertVulnType", err)
	return err
}
