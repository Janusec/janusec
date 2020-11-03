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
	const sqlCreateTableIfNotExistsVipTargets = `CREATE TABLE IF NOT EXISTS vip_targets(id bigserial PRIMARY KEY,vip_app_id bigint NOT NULL,destination varchar(128) NOT NULL)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsVipTargets)
	return err
}

// SelectVipTargetsByAppID ...
func (dal *MyDAL) SelectVipTargetsByAppID(vipAppID int64) []*models.VipTarget {
	targets := []*models.VipTarget{}
	const sqlSelectVipTargetsByAppID = `SELECT id,destination FROM vip_targets WHERE vip_app_id=$1`
	rows, err := dal.db.Query(sqlSelectVipTargetsByAppID, vipAppID)
	utils.CheckError("SelectDestinationsByAppID", err)
	if err != nil {
		return targets
	}
	defer rows.Close()
	for rows.Next() {
		vipTarget := &models.VipTarget{VipAppID: vipAppID, Online: true}
		err = rows.Scan(&vipTarget.ID, &vipTarget.Destination)
		if err != nil {
			utils.DebugPrintln("SelectDestinationsByAppID rows.Scan", err)
		}
		targets = append(targets, vipTarget)
	}
	return targets
}

// UpdateVipTarget ... update port forwarding target
func (dal *MyDAL) UpdateVipTarget(vipAppID int64, destination string, id int64) error {
	const sqlUpdateTarget = `UPDATE vip_targets SET vip_app_id=$1,destination=$2 WHERE id=$3`
	_, err := dal.db.Exec(sqlUpdateTarget, vipAppID, destination, id)
	utils.CheckError("UpdateVipTarget", err)
	return err
}

// InsertVipTarget create new VipTarget
func (dal *MyDAL) InsertVipTarget(vipAppID int64, destination string) (newID int64, err error) {
	const sqlInsertTarget = `INSERT INTO vip_targets(vip_app_id, destination) VALUES($1,$2) RETURNING id`
	err = dal.db.QueryRow(sqlInsertTarget, vipAppID, destination).Scan(&newID)
	utils.CheckError("InsertVipTarget", err)
	return newID, err
}

// DeleteVipTargetByID delete VipTarget by id
func (dal *MyDAL) DeleteVipTargetByID(id int64) error {
	const sqlDeleteVipTargetByID = `DELETE FROM vip_targets WHERE id=$1`
	_, err := dal.db.Exec(sqlDeleteVipTargetByID, id)
	utils.CheckError("DeleteDestinationByID", err)
	return err
}
