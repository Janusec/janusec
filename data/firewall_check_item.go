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
	sqlCreateTableIfNotExistCheckItems = `CREATE TABLE IF NOT EXISTS check_items(id bigserial primary key,check_point bigint,operation bigint,key_name varchar(256),regex_policy varchar(512),group_policy_id bigint)`
	sqlInsertCheckItem                 = `INSERT INTO check_items(check_point,operation,key_name,regex_policy,group_policy_id) VALUES($1,$2,$3,$4,$5) RETURNING id`
	sqlSelectCheckItemsByGroupID       = `SELECT id,check_point,operation,key_name,regex_policy FROM check_items WHERE group_policy_id=$1`
	sqlDeleteCheckItemByID             = `DELETE FROM check_items WHERE id=$1`
	sqlUpdateCheckItemByID             = `UPDATE check_items SET check_point=$1,operation=$2,key_name=$3,regex_policy=$4,group_policy_id=$5 WHERE id=$6`
	//sqlDeleteCheckItemsByGroupID       = `DELETE FROM check_items WHERE group_policy_id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistCheckItems() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistCheckItems)
	utils.CheckError("CreateTableIfNotExistCheckItems", err)
	return err
}

func (dal *MyDAL) InsertCheckItem(checkPoint models.ChkPoint, operation models.Operation, keyName string, regexPolicy string, groupPolicyID int64) (newID int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertCheckItem)
	utils.CheckError("sqlInsertCheckItem Prepare", err)
	defer stmt.Close()
	err = stmt.QueryRow(checkPoint, operation, keyName, regexPolicy, groupPolicyID).Scan(&newID)
	utils.CheckError("sqlInsertCheckItem Scan", err)
	return newID, err
}

func (dal *MyDAL) SelectCheckItemsByGroupID(groupPolicyID int64) (checkItems []*models.CheckItem, err error) {
	rows, err := dal.db.Query(sqlSelectCheckItemsByGroupID, groupPolicyID)
	utils.CheckError("SelectCheckItemsByGroupID", err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		checkItem := new(models.CheckItem)
		err = rows.Scan(&checkItem.ID, &checkItem.CheckPoint, &checkItem.Operation, &checkItem.KeyName, &checkItem.RegexPolicy)
		utils.CheckError("SelectCheckItemsByGroupID Scan", err)
		checkItems = append(checkItems, checkItem)
	}
	return checkItems, nil
}

func (dal *MyDAL) DeleteCheckItemByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteCheckItemByID, id)
	utils.CheckError("DeleteCheckItemByID", err)
	return err
}

/*
func (dal *MyDAL) DeleteCheckItemsByGroupID(group_policy_id int64) error {
	_, err := dal.db.Exec(sqlDeleteCheckItemsByGroupID, group_policy_id)
	utils.CheckError("DeleteCheckItemsByGroupID", err)
	return err
}
*/

func (dal *MyDAL) UpdateCheckItemByID(checkPoint models.ChkPoint, operation models.Operation, keyName string, regexPolicy string, groupPolicyID int64, checkItemID int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateCheckItemByID)
	utils.CheckError("UpdateCheckItemByID Prepare", err)
	defer stmt.Close()
	_, err = stmt.Exec(checkPoint, operation, keyName, regexPolicy, groupPolicyID, checkItemID)
	utils.CheckError("UpdateCheckItemByID Exec", err)
	return err
}
