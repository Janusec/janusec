/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-11-01 09:14:07
 * @Last Modified: U2, 2020-11-01 09:14:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsVipApplications ...
func (dal *MyDAL) CreateTableIfNotExistsVipApplications() error {
	const sqlCreateTableIfNotExistsVipApplications = `CREATE TABLE IF NOT EXISTS vip_apps(id bigserial PRIMARY KEY, name varchar(128) NOT NULL, listen_port bigint, is_tcp boolean default true, owner varchar(128), description varchar(256))`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVipApplications)
	return err
}

// SelectVipApplications ...
func (dal *MyDAL) SelectVipApplications() []*models.VipApp {
	const sqlSelectVipApplications = `SELECT id,name,listen_port,is_tcp,owner,description FROM vip_apps`
	rows, err := dal.db.Query(sqlSelectVipApplications)
	utils.CheckError("SelectVipApplications", err)
	defer rows.Close()
	var vipApps = []*models.VipApp{}
	for rows.Next() {
		vipApp := &models.VipApp{}
		err = rows.Scan(
			&vipApp.ID,
			&vipApp.Name,
			&vipApp.ListenPort,
			&vipApp.IsTCP,
			&vipApp.Owner,
			&vipApp.Description,
		)
		if err != nil {
			utils.DebugPrintln("SelectVipApplications rows.Scan", err)
		}
		vipApps = append(vipApps, vipApp)
	}
	return vipApps
}
