/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:48
 * @Last Modified: U2, 2018-07-14 16:24:48
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

const (
	sqlSelectAllNodes              = `SELECT id,version,last_ip,last_req_time FROM nodes`
	sqlCreateTableIfNotExistsNodes = `CREATE TABLE IF NOT EXISTS nodes(id bigserial PRIMARY KEY,version varchar(128),last_ip varchar(128),last_req_time bigint)`
	sqlInsertNode                  = `INSERT INTO nodes(version,last_ip,last_req_time) VALUES($1,$2,$3) RETURNING id`
	sqlUpdateNodeLastInfo          = `UPDATE nodes SET version=$1,last_ip=$2,last_req_time=$3 WHERE id=$4`
	sqlDeleteNodeByID              = `DELETE FROM nodes WHERE id=$1`
	//sqlUpdateNodeName              = `UPDATE nodes SET name=$1 WHERE id=$2`
)

func (dal *MyDAL) DeleteNodeByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteNodeByID, id)
	return err
}

func (dal *MyDAL) SelectAllNodes() []*models.DBNode {
	rows, err := dal.db.Query(sqlSelectAllNodes)
	utils.CheckError("SelectAllNodes", err)
	defer rows.Close()
	var dbNodes []*models.DBNode
	for rows.Next() {
		dbNode := new(models.DBNode)
		err = rows.Scan(&dbNode.ID, &dbNode.Version, &dbNode.LastIP, &dbNode.LastRequestTime)
		dbNodes = append(dbNodes, dbNode)
	}
	return dbNodes
}

func (dal *MyDAL) CreateTableIfNotExistsNodes() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsNodes)
	return err
}

func (dal *MyDAL) InsertNode(version string, lastIP string, lastReqTime int64) (newID int64) {
	err := dal.db.QueryRow(sqlInsertNode, version, lastIP, lastReqTime).Scan(&newID)
	utils.CheckError("InsertNode", err)
	return newID
}

func (dal *MyDAL) UpdateNodeLastInfo(version string, lastIP string, lastReqTime int64, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateNodeLastInfo)
	defer stmt.Close()
	_, err = stmt.Exec(version, lastIP, lastReqTime, id)
	utils.CheckError("UpdateNodeLastInfo", err)
	return err
}

/*
func (dal *MyDAL) UpdateNodeName(name string, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateNodeName)
	defer stmt.Close()
	_, err = stmt.Exec(name, id)
	utils.CheckError("UpdateNodeName", err)
	return err
}
*/
