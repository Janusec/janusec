/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:06
 * @Last Modified: U2, 2018-07-14 16:31:06
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

const (
	sqlCreateTableIfNotExistsGroupPolicy = `CREATE TABLE IF NOT EXISTS group_policies(id bigserial primary key,description varchar(256),app_id bigint,vuln_id bigint,hit_value bigint,action bigint,is_enabled boolean,user_id bigint,update_time bigint)`
	sqlExistsGroupPolicy                 = `SELECT coalesce((SELECT 1 FROM group_policies limit 1),0)`
	sqlSelectGroupPolicies               = `SELECT id,description,app_id,vuln_id,hit_value,action,is_enabled,user_id,update_time FROM group_policies`
	sqlSelectGroupPoliciesByAppID        = `SELECT id,description,vuln_id,hit_value,action,is_enabled,user_id,update_time FROM group_policies WHERE app_id=$1`
	sqlInsertGroupPolicy                 = `INSERT INTO group_policies(description,app_id,vuln_id,hit_value,action,is_enabled,user_id,update_time) values($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`
	sqlUpdateGroupPolicy                 = `UPDATE group_policies SET description=$1,app_id=$2,vuln_id=$3,hit_value=$4,action=$5,is_enabled=$6,user_id=$7,update_time=$8 WHERE id=$9`
	sqlDeleteGroupPolicyByID             = `DELETE FROM group_policies WHERE id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistsGroupPolicy() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsGroupPolicy)
	utils.CheckError("CreateTableIfNotExistsGroupPolicy", err)
	return err
}

func (dal *MyDAL) DeleteGroupPolicyByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteGroupPolicyByID, id)
	utils.CheckError("DeleteGroupPolicyByID", err)
	return err
}

func (dal *MyDAL) UpdateGroupPolicy(description string, appID int64, vulnID int64, hitValue int64, action models.PolicyAction, isEnabled bool, userID int64, updateTime int64, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateGroupPolicy)
	defer stmt.Close()
	_, err = stmt.Exec(description, appID, vulnID, hitValue, action, isEnabled, userID, updateTime, id)
	utils.CheckError("UpdateGroupPolicy", err)
	return err
}

func (dal *MyDAL) SelectGroupPolicies() (groupPolicies []*models.GroupPolicy) {
	rows, err := dal.db.Query(sqlSelectGroupPolicies)
	utils.CheckError("SelectGroupPolicies", err)
	defer rows.Close()
	for rows.Next() {
		groupPolicy := new(models.GroupPolicy)
		err = rows.Scan(&groupPolicy.ID, &groupPolicy.Description, &groupPolicy.AppID, &groupPolicy.VulnID,
			&groupPolicy.HitValue, &groupPolicy.Action, &groupPolicy.IsEnabled, &groupPolicy.UserID, &groupPolicy.UpdateTime)
		utils.CheckError("SelectGroupPolicies Scan", err)
		groupPolicies = append(groupPolicies, groupPolicy)
	}
	return groupPolicies
}

func (dal *MyDAL) SelectGroupPoliciesByAppID(appID int64) (groupPolicies []*models.GroupPolicy, err error) {
	rows, err := dal.db.Query(sqlSelectGroupPoliciesByAppID, appID)
	utils.CheckError("SelectGroupPoliciesByAppID", err)
	defer rows.Close()
	for rows.Next() {
		groupPolicy := new(models.GroupPolicy)
		groupPolicy.AppID = appID
		err = rows.Scan(&groupPolicy.ID, &groupPolicy.Description, &groupPolicy.VulnID,
			&groupPolicy.HitValue, &groupPolicy.Action, &groupPolicy.IsEnabled, &groupPolicy.UserID, &groupPolicy.UpdateTime)
		utils.CheckError("SelectGroupPoliciesByAppID Scan", err)
		if err != nil {
			return groupPolicies, err
		}
		groupPolicies = append(groupPolicies, groupPolicy)
	}
	return groupPolicies, err
}

func (dal *MyDAL) InsertGroupPolicy(description string, appID int64, vulnID int64, hitValue int64, action models.PolicyAction, isEnabled bool, userID int64, updateTime int64) (newID int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertGroupPolicy)
	utils.CheckError("InsertGroupPolicy Prepare", err)
	defer stmt.Close()
	err = stmt.QueryRow(description, appID, vulnID, hitValue, action, isEnabled, userID, updateTime).Scan(&newID)
	utils.CheckError("InsertGroupPolicy Scan", err)
	return newID, err
}

func (dal *MyDAL) ExistsGroupPolicy() bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsGroupPolicy).Scan(&exist)
	utils.CheckError("ExistsGroupPolicy", err)
	if exist == 0 {
		return false
	} else {
		return true
	}
}
