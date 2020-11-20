/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:25:23
 * @Last Modified: U2, 2018-07-14 16:25:23
 */

package data

import (
	"janusec/utils"
)

const (
	sqlSetIDSeqStartWith = `SELECT setval($1,$2,false)`
)

func (dal *MyDAL) SetIDSeqStartWith(tableName string, seq int64) error {
	tableIDSeq := tableName + `_id_seq`
	_, err := dal.db.Exec(sqlSetIDSeqStartWith, tableIDSeq, seq)
	if err != nil {
		tableIDSeq := `"` + tableName + `_id_SEQ"`
		_, err = dal.db.Exec(sqlSetIDSeqStartWith, tableIDSeq, seq)
		utils.CheckError("SetIDSeqStartWith", err)
	}
	return err
}
