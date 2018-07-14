/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:06
 * @Last Modified: U2, 2018-07-14 16:31:06
 */

package data

import (
	"../models"
	"../utils"
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

func (dal *MyDAL) UpdateGroupPolicy(description string, app_id int64, vuln_id int64, hit_value int64, action models.PolicyAction, is_enabled bool, user_id int64, update_time int64, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateGroupPolicy)
	defer stmt.Close()
	_, err = stmt.Exec(description, app_id, vuln_id, hit_value, action, is_enabled, user_id, update_time, id)
	utils.CheckError("UpdateGroupPolicy", err)
	return err
}

func (dal *MyDAL) SelectGroupPolicies() (group_policies []*models.GroupPolicy) {
	rows, err := dal.db.Query(sqlSelectGroupPolicies)
	utils.CheckError("SelectGroupPolicies", err)
	defer rows.Close()
	for rows.Next() {
		group_policy := new(models.GroupPolicy)
		err = rows.Scan(&group_policy.ID, &group_policy.Description, &group_policy.AppID, &group_policy.VulnID,
			&group_policy.HitValue, &group_policy.Action, &group_policy.IsEnabled, &group_policy.UserID, &group_policy.UpdateTime)
		utils.CheckError("SelectGroupPolicies Scan", err)
		group_policies = append(group_policies, group_policy)
	}
	return group_policies
}

func (dal *MyDAL) SelectGroupPoliciesByAppID(app_id int64) (group_policies []*models.GroupPolicy, err error) {
	rows, err := dal.db.Query(sqlSelectGroupPoliciesByAppID, app_id)
	utils.CheckError("SelectGroupPoliciesByAppID", err)
	defer rows.Close()
	for rows.Next() {
		group_policy := new(models.GroupPolicy)
		group_policy.AppID = app_id
		err = rows.Scan(&group_policy.ID, &group_policy.Description, &group_policy.VulnID,
			&group_policy.HitValue, &group_policy.Action, &group_policy.IsEnabled, &group_policy.UserID, &group_policy.UpdateTime)
		utils.CheckError("SelectGroupPoliciesByAppID Scan", err)
		if err != nil {
			return group_policies, err
		}
		group_policies = append(group_policies, group_policy)
	}
	return group_policies, err
}

func (dal *MyDAL) InsertGroupPolicy(description string, app_id int64, vuln_id int64, hit_value int64, action models.PolicyAction, is_enabled bool, user_id int64, update_time int64) (new_id int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertGroupPolicy)
	utils.CheckError("InsertGroupPolicy Prepare", err)
	defer stmt.Close()
	err = stmt.QueryRow(description, app_id, vuln_id, hit_value, action, is_enabled, user_id, update_time).Scan(&new_id)
	utils.CheckError("InsertGroupPolicy Scan", err)
	return new_id, err
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
