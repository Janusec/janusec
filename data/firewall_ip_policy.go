/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2021-01-09 22:25:00
 * @Last Modified: U2, 2021-01-09 22:25:00
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsIPPolicies ...
func (dal *MyDAL) CreateTableIfNotExistsIPPolicies() error {
	const sqlCreateTableIfNotExistsIPPolicies = `CREATE TABLE IF NOT EXISTS "ip_policies"("id" bigserial PRIMARY KEY, "ip_addr" VARCHAR(128) NOT NULL, "is_allow" boolean, "apply_to_waf" boolean, "apply_to_cc" boolean)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsIPPolicies)
	return err
}

// InsertIPPolicy Insert IP Address to "ip_policies"
func (dal *MyDAL) InsertIPPolicy(ipAddr string, isAllow bool, applyToWAF bool, applyToCC bool) (newID int64) {
	const sqlInsertIPPolicy = `INSERT INTO "ip_policies"("ip_addr","is_allow","apply_to_waf","apply_to_cc") VALUES($1,$2,$3,$4) RETURNING "id"`
	err := dal.db.QueryRow(sqlInsertIPPolicy, ipAddr, isAllow, applyToWAF, applyToCC).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertIPPolicy", err)
	}
	return newID
}

// UpdateIPPolicy update IP address and policy
func (dal *MyDAL) UpdateIPPolicy(id int64, ipAddr string, isAllow bool, applyToWAF bool, applyToCC bool) error {
	const sqlUpdateIPPolicy = `UPDATE "ip_policies" SET "ip_addr"=$1,"is_allow"=$2,"apply_to_waf"=$3,"apply_to_cc"=$4 WHERE "id"=$5`
	_, err := dal.db.Exec(sqlUpdateIPPolicy, ipAddr, isAllow, applyToWAF, applyToCC, id)
	return err
}

// DeleteIPPolicyByID ...
func (dal *MyDAL) DeleteIPPolicyByID(id int64) error {
	const sqlDeleteIPPolicyByID = `DELETE FROM "ip_policies" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDeleteIPPolicyByID, id)
	return err
}

// LoadIPPolicies return the list of IPPolicy
func (dal *MyDAL) LoadIPPolicies() []*models.IPPolicy {
	const sqlSelectAllowList = `SELECT "id","ip_addr","is_allow","apply_to_waf","apply_to_cc" FROM "ip_policies"`
	rows, err := dal.db.Query(sqlSelectAllowList)
	if err != nil {
		utils.DebugPrintln("GetIPPolicies", err)
	}
	defer rows.Close()
	var ipPolicies = []*models.IPPolicy{}
	for rows.Next() {
		ipPolicy := &models.IPPolicy{}
		err = rows.Scan(
			&ipPolicy.ID,
			&ipPolicy.IPAddr,
			&ipPolicy.IsAllow,
			&ipPolicy.ApplyToWAF,
			&ipPolicy.ApplyToCC)
		if err != nil {
			utils.DebugPrintln("GetIPPolicies rows.Scan", err)
		}
		ipPolicies = append(ipPolicies, ipPolicy)
	}
	return ipPolicies
}
