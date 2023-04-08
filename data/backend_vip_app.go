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
	const sqlCreateTableIfNotExistsVipApplications = `CREATE TABLE IF NOT EXISTS "vip_apps"("id" bigserial PRIMARY KEY, "name" VARCHAR(128) NOT NULL, "listen_port" bigint, "is_tcp" boolean default true, "owner" VARCHAR(128) NOT NULL DEFAULT '', "description" VARCHAR(256) NOT NULL DEFAULT '')`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVipApplications)
	return err
}

// SelectVipApplications ...
func (dal *MyDAL) SelectVipApplications() []*models.VipApp {
	const sqlSelectVipApplications = `SELECT "id","name","listen_port","is_tcp","owner","description" FROM "vip_apps"`
	rows, err := dal.db.Query(sqlSelectVipApplications)
	if err != nil {
		utils.DebugPrintln("SelectVipApplications", err)
	}
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

// InsertVipApp create new port forwarding
func (dal *MyDAL) InsertVipApp(vipAppName string, listenPort int64, isTCP bool, owner string, description string) (newID int64) {
	const sqlInsertVipApp = `INSERT INTO "vip_apps"("id","name","listen_port","is_tcp","owner","description") VALUES($1,$2,$3,$4,$5,$6) RETURNING "id"`
	snowID := utils.GenSnowflakeID()
	err := dal.db.QueryRow(sqlInsertVipApp, snowID, vipAppName, listenPort, isTCP, owner, description).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertVipApp", err)
	}
	return newID
}

// UpdateVipAppByID update an existed VipApp
func (dal *MyDAL) UpdateVipAppByID(vipAppName string, listenPort int64, isTCP bool, owner string, description string, vipAppID int64) error {
	const sqlUpdateVipApp = `UPDATE "vip_apps" SET "name"=$1,"listen_port"=$2,"is_tcp"=$3,"owner"=$4,"description"=$5 WHERE "id"=$6`
	_, err := dal.db.Exec(sqlUpdateVipApp, vipAppName, listenPort, isTCP, owner, description, vipAppID)
	if err != nil {
		utils.DebugPrintln("InsertVipApp", err)
	}
	return err
}

// DeleteVipAppByID ...
func (dal *MyDAL) DeleteVipAppByID(id int64) error {
	const sqlDeleteVipAppByID = `DELETE FROM "vip_apps" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDeleteVipAppByID, id)
	if err != nil {
		utils.DebugPrintln("DeleteVipAppByID", err)
	}
	return err
}
