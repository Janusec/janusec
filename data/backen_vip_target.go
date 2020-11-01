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

//
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
