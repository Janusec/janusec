/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:43
 * @Last Modified: U2, 2018-07-14 16:25:43
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistCheckItems = `CREATE TABLE IF NOT EXISTS "check_items"("id" bigserial primary key,"check_point" bigint,"operation" bigint,"key_name" VARCHAR(256) NOT NULL DEFAULT '',"regex_policy" VARCHAR(512) NOT NULL,"group_policy_id" bigint)`
	sqlInsertCheckItem                 = `INSERT INTO "check_items"("check_point","operation","key_name","regex_policy","group_policy_id") VALUES($1,$2,$3,$4,$5) RETURNING "id"`
	sqlSelectCheckItemsByGroupID       = `SELECT "id","check_point","operation","key_name","regex_policy" FROM "check_items" WHERE "group_policy_id"=$1`
	sqlDeleteCheckItemByID             = `DELETE FROM "check_items" WHERE "id"=$1`
	sqlUpdateCheckItemByID             = `UPDATE "check_items" SET "check_point"=$1,"operation"=$2,"key_name"=$3,"regex_policy"=$4,"group_policy_id"=$5 WHERE "id"=$6`
)

// CreateTableIfNotExistCheckItems ...
func (dal *MyDAL) CreateTableIfNotExistCheckItems() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistCheckItems)
	if err != nil {
		utils.DebugPrintln("CreateTableIfNotExistCheckItems", err)
	}
	return err
}

// InsertCheckItem ...
func (dal *MyDAL) InsertCheckItem(checkPoint models.ChkPoint, operation models.Operation, keyName string, regexPolicy string, groupPolicyID int64) (newID int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertCheckItem)
	if err != nil {
		utils.DebugPrintln("sqlInsertCheckItem Prepare", err)
	}
	defer stmt.Close()
	err = stmt.QueryRow(checkPoint, operation, keyName, regexPolicy, groupPolicyID).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("sqlInsertCheckItem Scan", err)
	}
	return newID, err
}

// SelectCheckItemsByGroupID ...
func (dal *MyDAL) SelectCheckItemsByGroupID(groupPolicyID int64) ([]*models.DBCheckItem, error) {
	checkItems := []*models.DBCheckItem{}
	rows, err := dal.db.Query(sqlSelectCheckItemsByGroupID, groupPolicyID)
	if err != nil {
		utils.DebugPrintln("SelectCheckItemsByGroupID", err)
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		checkItem := &models.DBCheckItem{}
		err = rows.Scan(&checkItem.ID, &checkItem.CheckPoint, &checkItem.Operation, &checkItem.KeyName, &checkItem.RegexPolicy)
		if err != nil {
			utils.DebugPrintln("SelectCheckItemsByGroupID Scan", err)
		}
		checkItems = append(checkItems, checkItem)
	}
	return checkItems, nil
}

// DeleteCheckItemByID ...
func (dal *MyDAL) DeleteCheckItemByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteCheckItemByID, id)
	if err != nil {
		utils.DebugPrintln("DeleteCheckItemByID", err)
	}
	return err
}

// UpdateCheckItemByID ...
func (dal *MyDAL) UpdateCheckItemByID(checkPoint models.ChkPoint, operation models.Operation, keyName string, regexPolicy string, groupPolicyID int64, checkItemID int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateCheckItemByID)
	if err != nil {
		utils.DebugPrintln("UpdateCheckItemByID Prepare", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(checkPoint, operation, keyName, regexPolicy, groupPolicyID, checkItemID)
	if err != nil {
		utils.DebugPrintln("UpdateCheckItemByID Exec", err)
	}
	return err
}
