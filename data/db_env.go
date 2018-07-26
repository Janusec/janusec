/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:23
 * @Last Modified: U2, 2018-07-14 16:25:23
 */

package data

import (
	"github.com/Janusec/janusec/utils"
)

const (
	sqlSetIDSeqStartWith = `SELECT setval($1,$2,false)`
)

func (dal *MyDAL) SetIDSeqStartWith(table_name string, seq int64) error {
	table_id_sqq := table_name + `_id_seq`
	_, err := dal.db.Exec(sqlSetIDSeqStartWith, table_id_sqq, seq)
	utils.CheckError("SetIDSeqStartWith", err)
	return err
}
