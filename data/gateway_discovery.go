/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-03-11 19:23:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsDiscoveryRules create table discovery_rules
func (dal *MyDAL) CreateTableIfNotExistsDiscoveryRules() error {
	const sqlCreateTableIfNotExistsDiscoveryRules = `CREATE TABLE IF NOT EXISTS "discovery_rules"("id" bigserial PRIMARY KEY, "field_name" VARCHAR(256) NOT NULL, "sample" VARCHAR(512) NOT NULL, "regex" VARCHAR(512) NOT NULL, "description" VARCHAR(512) NOT NULL, "editor" VARCHAR(256) NOT NULL, "update_time" bigint)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDiscoveryRules)
	return err
}

func (dal *MyDAL) InsertDiscoveryRule(discoveryRule *models.DiscoveryRule) (newID int64, err error) {
	const sqlInsertDiscoveryRule = `INSERT INTO "discovery_rules"("id","field_name", "sample", "regex", "description", "editor", "update_time") VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`
	snowID := utils.GenSnowflakeID()
	err = dal.db.QueryRow(sqlInsertDiscoveryRule, snowID, discoveryRule.FieldName, discoveryRule.Sample, discoveryRule.Regex, discoveryRule.Description, discoveryRule.Editor, discoveryRule.UpdateTime).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertDiscoveryRule", err)
	}
	return newID, err
}

func (dal *MyDAL) GetAllDiscoveryRules() ([]*models.DiscoveryRule, error) {
	const sqlSelectAll = `SELECT * FROM "discovery_rules"`
	rows, err := dal.db.Query(sqlSelectAll)
	if err != nil {
		utils.DebugPrintln("GetAllDiscoveryRules", err)
		return []*models.DiscoveryRule{}, err
	}
	defer rows.Close()
	var discoveryRules []*models.DiscoveryRule
	for rows.Next() {
		discoveryRule := &models.DiscoveryRule{}
		err = rows.Scan(
			&discoveryRule.ID,
			&discoveryRule.FieldName,
			&discoveryRule.Sample,
			&discoveryRule.Regex,
			&discoveryRule.Description,
			&discoveryRule.Editor,
			&discoveryRule.UpdateTime)
		if err != nil {
			utils.DebugPrintln("GetAllDiscoveryRules rows.Scan", err)
		}
		discoveryRules = append(discoveryRules, discoveryRule)
	}
	return discoveryRules, err
}

func (dal *MyDAL) UpdateDiscoveryRule(discoveryRule *models.DiscoveryRule) error {
	const sqlUpdateDiscoveryRule = `UPDATE "discovery_rules" SET "field_name"=$1, "sample"=$2, "regex"=$3, "description"=$4, "editor"=$5, "update_time"=$6 WHERE "id"=$7`
	_, err := dal.db.Exec(sqlUpdateDiscoveryRule, discoveryRule.FieldName, discoveryRule.Sample, discoveryRule.Regex, discoveryRule.Description, discoveryRule.Editor, discoveryRule.UpdateTime, discoveryRule.ID)
	if err != nil {
		utils.DebugPrintln("UpdateDiscoveryRule", err)
	}
	return err
}

// DeleteDiscoveryRuleByID ...
func (dal *MyDAL) DeleteDiscoveryRuleByID(id int64) error {
	const sqlDeleteDiscoveryRuleByID = `DELETE FROM "discovery_rules" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDeleteDiscoveryRuleByID, id)
	if err != nil {
		utils.DebugPrintln("DeleteDiscoveryRuleByID", err)
	}
	return err
}
