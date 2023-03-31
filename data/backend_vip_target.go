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

// CreateTableIfNotExistsVipTargets create vip_targets
func (dal *MyDAL) CreateTableIfNotExistsVipTargets() error {
	const sqlCreateTableIfNotExistsVipTargets = `CREATE TABLE IF NOT EXISTS "vip_targets"("id" bigserial PRIMARY KEY, "vip_app_id" bigint NOT NULL,"route_type" bigint default 1, "destination" VARCHAR(128) DEFAULT '',"pods_api" VARCHAR(512) DEFAULT '',"pod_port" VARCHAR(128) DEFAULT '',"pods" VARCHAR(1024) DEFAULT '')`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVipTargets)
	return err
}

// SelectVipTargetsByAppID ...
func (dal *MyDAL) SelectVipTargetsByAppID(vipAppID int64) []*models.VipTarget {
	targets := []*models.VipTarget{}
	const sqlSelectVipTargetsByAppID = `SELECT "id","route_type","destination","pods_api","pod_port" FROM "vip_targets" WHERE "vip_app_id"=$1`
	rows, err := dal.db.Query(sqlSelectVipTargetsByAppID, vipAppID)
	if err != nil {
		utils.DebugPrintln("SelectVipTargetsByAppID", err)
		return targets
	}
	defer rows.Close()
	for rows.Next() {
		vipTarget := &models.VipTarget{VipAppID: vipAppID, Online: true}
		err = rows.Scan(&vipTarget.ID, &vipTarget.RouteType, &vipTarget.Destination, &vipTarget.PodsAPI, &vipTarget.PodPort)
		if err != nil {
			utils.DebugPrintln("SelectVipTargetsByAppID rows.Scan", err)
		}
		targets = append(targets, vipTarget)
	}
	return targets
}

// UpdateVipTarget ... update port forwarding target
func (dal *MyDAL) UpdateVipTarget(vipAppID int64, routeType int64, destination string, podsAPI string, podPort string, id int64) error {
	const sqlUpdateTarget = `UPDATE "vip_targets" SET "vip_app_id"=$1,"route_type"=$2,"destination"=$3,"pods_api"=$4,"pod_port"=$5 WHERE "id"=$6`
	_, err := dal.db.Exec(sqlUpdateTarget, vipAppID, routeType, destination, podsAPI, podPort, id)
	if err != nil {
		utils.DebugPrintln("UpdateVipTarget", err)
	}
	return err
}

// InsertVipTarget create new VipTarget
func (dal *MyDAL) InsertVipTarget(vipAppID int64, routeType int64, destination string, podsAPI string, podPort string) (newID int64, err error) {
	const sqlInsertTarget = `INSERT INTO "vip_targets"("id","vip_app_id", "route_type", "destination", "pods_api", "pod_port") VALUES($1,$2,$3,$4,$5,$6) RETURNING "id"`
	snakeID := utils.GenSnowflakeID()
	err = dal.db.QueryRow(sqlInsertTarget, snakeID, vipAppID, routeType, destination, podsAPI, podPort).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertVipTarget", err)
	}
	return newID, err
}

// DeleteVipTargetByID delete VipTarget by id
func (dal *MyDAL) DeleteVipTargetByID(id int64) error {
	const sqlDeleteVipTargetByID = `DELETE FROM "vip_targets" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDeleteVipTargetByID, id)
	if err != nil {
		utils.DebugPrintln("DeleteDestinationByID", err)
	}
	return err
}

// DeleteVipTargetsByVipAppID delete all targets for one port forwarding app
func (dal *MyDAL) DeleteVipTargetsByVipAppID(vipAppID int64) error {
	const sqlDeleteVipTargetsByVipAppID = `DELETE FROM "vip_targets" WHERE "vip_app_id"=$1`
	_, err := dal.db.Exec(sqlDeleteVipTargetsByVipAppID, vipAppID)
	if err != nil {
		utils.DebugPrintln("DeleteVipTargetsByVipAppID", err)
	}
	return err
}
