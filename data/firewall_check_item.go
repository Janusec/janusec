/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:43
 * @Last Modified: U2, 2018-07-14 16:25:43
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
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

func (dal *MyDAL) InsertCheckItem(check_point models.ChkPoint, operation models.Operation, key_name string, regex_policy string, group_policy_id int64) (new_id int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertCheckItem)
	utils.CheckError("sqlInsertCheckItem Prepare", err)
	defer stmt.Close()
	err = stmt.QueryRow(check_point, operation, key_name, regex_policy, group_policy_id).Scan(&new_id)
	utils.CheckError("sqlInsertCheckItem Scan", err)
	return new_id, err
}

func (dal *MyDAL) SelectCheckItemsByGroupID(group_policy_id int64) (check_items []*models.CheckItem, err error) {
	rows, err := dal.db.Query(sqlSelectCheckItemsByGroupID, group_policy_id)
	utils.CheckError("SelectCheckItemsByGroupID", err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		check_item := new(models.CheckItem)
		err = rows.Scan(&check_item.ID, &check_item.CheckPoint, &check_item.Operation, &check_item.KeyName, &check_item.RegexPolicy)
		utils.CheckError("SelectCheckItemsByGroupID Scan", err)
		check_items = append(check_items, check_item)
	}
	return check_items, nil
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

func (dal *MyDAL) UpdateCheckItemByID(check_point models.ChkPoint, operation models.Operation, key_name string, regex_policy string, group_policy_id int64, check_item_id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateCheckItemByID)
	utils.CheckError("UpdateCheckItemByID Prepare", err)
	defer stmt.Close()
	_, err = stmt.Exec(check_point, operation, key_name, regex_policy, group_policy_id, check_item_id)
	utils.CheckError("UpdateCheckItemByID Exec", err)
	return err
}
