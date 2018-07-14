/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:35
 * @Last Modified: U2, 2018-07-14 16:25:35
 */

package data

import (
	"time"

	"../models"
	"../utils"
)

const (
	sqlCreateTableIfNotExistsCCPolicy = `CREATE TABLE IF NOT EXISTS ccpolicies(app_id bigint primary key,interval_seconds bigint,max_count bigint,block_seconds bigint,action bigint,stat_by_url boolean,stat_by_ua boolean,stat_by_cookie boolean,is_enabled boolean)`
	sqlExistsCCPolicy                 = `SELECT coalesce((SELECT 1 FROM ccpolicies LIMIT 1),0)`
	sqlExistsCCPolicyByAppID          = `SELECT coalesce((SELECT 1 FROM ccpolicies WHERE app_id=$1 LIMIT 1),0)`
	sqlInsertCCPolicy                 = `INSERT INTO ccpolicies(app_id,interval_seconds,max_count,block_seconds,action,stat_by_url,stat_by_ua,stat_by_cookie,is_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	sqlSelectCCPolicies               = `SELECT app_id,interval_seconds,max_count,block_seconds,action,stat_by_url,stat_by_ua,stat_by_cookie,is_enabled FROM ccpolicies`
	sqlUpdateCCPolicy                 = `UPDATE ccpolicies SET interval_seconds=$1,max_count=$2,block_seconds=$3,action=$4,stat_by_url=$5,stat_by_ua=$6,stat_by_cookie=$7,is_enabled=$8 where app_id=$9`
	sqlDeleteCCPolicy                 = `DELETE FROM ccpolicies WHERE app_id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistsCCPolicy() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCCPolicy)
	return err
}

func (dal *MyDAL) DeleteCCPolicy(app_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteCCPolicy)
	defer stmt.Close()
	_, err = stmt.Exec(app_id)
	utils.CheckError("DeleteCCPolicy", err)
	return err
}

func (dal *MyDAL) UpdateCCPolicy(interval_seconds time.Duration, max_count int64,
	block_seconds time.Duration, action models.PolicyAction,
	stat_by_url bool, stat_by_ua bool, stat_by_cookie bool, is_enabled bool, app_id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateCCPolicy)
	defer stmt.Close()
	_, err = stmt.Exec(interval_seconds, max_count, block_seconds, action,
		stat_by_url, stat_by_ua, stat_by_cookie, is_enabled, app_id)
	utils.CheckError("UpdateCCPolicy", err)
	return err
}

func (dal *MyDAL) ExistsCCPolicy() bool {
	var exist_cc_policy int
	err := dal.db.QueryRow(sqlExistsCCPolicy).Scan(&exist_cc_policy)
	utils.CheckError("ExistsCCPolicy", err)
	if exist_cc_policy == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) ExistsCCPolicyByAppID(app_id int64) bool {
	var exist_cc_policy int
	err := dal.db.QueryRow(sqlExistsCCPolicyByAppID, app_id).Scan(&exist_cc_policy)
	utils.CheckError("ExistsCCPolicyByAppID", err)
	if exist_cc_policy == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) InsertCCPolicy(app_id int64, interval_seconds time.Duration, max_count int64, block_seconds time.Duration,
	action models.PolicyAction, stat_by_url bool, stat_by_ua bool, stat_by_cookie bool, is_enabled bool) error {
	_, err := dal.db.Exec(sqlInsertCCPolicy, app_id, interval_seconds, max_count, block_seconds,
		action, stat_by_url, stat_by_ua, stat_by_cookie, is_enabled)
	utils.CheckError("InsertCCPolicy", err)
	return err
}

func (dal *MyDAL) SelectCCPolicies() (cc_policies []*models.CCPolicy) {
	rows, err := dal.db.Query(sqlSelectCCPolicies)
	utils.CheckError("SelectCCPolicies", err)
	defer rows.Close()
	for rows.Next() {
		cc_policy := new(models.CCPolicy)
		rows.Scan(&cc_policy.AppID, &cc_policy.IntervalSeconds, &cc_policy.MaxCount, &cc_policy.BlockSeconds,
			&cc_policy.Action, &cc_policy.StatByURL, &cc_policy.StatByUserAgent, &cc_policy.StatByCookie, &cc_policy.IsEnabled)
		cc_policies = append(cc_policies, cc_policy)
	}
	return cc_policies
}
