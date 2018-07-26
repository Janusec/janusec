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
	sqlSelectAllNodes              = `SELECT id,key,name,version,last_ip,last_req_time FROM nodes`
	sqlCreateTableIfNotExistsNodes = `CREATE TABLE IF NOT EXISTS nodes(id bigserial PRIMARY KEY,key varchar(256),name varchar(256),version varchar(128),last_ip varchar(128),last_req_time bigint)`
	sqlInsertNode                  = `INSERT INTO nodes(key,name,version,last_ip,last_req_time) VALUES($1,$2,$3,$4,$5) RETURNING id`
	sqlUpdateNodeLastInfo          = `UPDATE nodes SET version=$1,last_ip=$2,last_req_time=$3 WHERE id=$4`
	sqlUpdateNodeName              = `UPDATE nodes SET name=$1 WHERE id=$2`
)

func (dal *MyDAL) SelectAllNodes() []*models.DBNode {
	rows, err := dal.db.Query(sqlSelectAllNodes)
	utils.CheckError("SelectAllNodes", err)
	defer rows.Close()
	var db_nodes []*models.DBNode
	for rows.Next() {
		db_node := new(models.DBNode)
		err = rows.Scan(&db_node.ID, &db_node.EncryptedKey, &db_node.Name, &db_node.Version, &db_node.LastIP, &db_node.LastRequestTime)
		db_nodes = append(db_nodes, db_node)
	}
	return db_nodes
}

func (dal *MyDAL) CreateTableIfNotExistsNodes() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsNodes)
	return err
}

func (dal *MyDAL) InsertNode(hex_key string, name string, version string, last_ip string, last_req_time int64) (new_id int64) {
	err := dal.db.QueryRow(sqlInsertNode, hex_key, name, version, last_ip, last_req_time).Scan(&new_id)
	utils.CheckError("InsertNode", err)
	return new_id
}

func (dal *MyDAL) UpdateNodeLastInfo(version string, last_ip string, last_req_time int64, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateNodeLastInfo)
	defer stmt.Close()
	_, err = stmt.Exec(version, last_ip, last_req_time, id)
	utils.CheckError("UpdateNodeLastInfo", err)
	return err
}

func (dal *MyDAL) UpdateNodeName(name string, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateNodeName)
	defer stmt.Close()
	_, err = stmt.Exec(name, id)
	utils.CheckError("UpdateNodeName", err)
	return err
}
