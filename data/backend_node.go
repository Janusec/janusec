/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:48
 * @Last Modified: U2, 2018-07-14 16:24:48
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlSelectAllNodes              = `SELECT "id","version","last_ip","last_req_time" FROM "nodes"`
	sqlCreateTableIfNotExistsNodes = `CREATE TABLE IF NOT EXISTS "nodes"("id" bigserial PRIMARY KEY,"version" VARCHAR(128) NOT NULL,"last_ip" VARCHAR(128) NOT NULL,"last_req_time" bigint)`
	sqlInsertNode                  = `INSERT INTO "nodes"("version","last_ip","last_req_time") VALUES($1,$2,$3) RETURNING "id"`
	sqlUpdateNodeLastInfo          = `UPDATE "nodes" SET "version"=$1,"last_ip"=$2,"last_req_time"=$3 WHERE "id"=$4`
	sqlDeleteNodeByID              = `DELETE FROM "nodes" WHERE "id"=$1`
)

// DeleteNodeByID ...
func (dal *MyDAL) DeleteNodeByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteNodeByID, id)
	return err
}

// SelectAllNodes ...
func (dal *MyDAL) SelectAllNodes() []*models.DBNode {
	rows, err := dal.db.Query(sqlSelectAllNodes)
	utils.CheckError("SelectAllNodes", err)
	defer rows.Close()
	dbNodes := []*models.DBNode{}
	for rows.Next() {
		dbNode := &models.DBNode{}
		_ = rows.Scan(&dbNode.ID, &dbNode.Version, &dbNode.LastIP, &dbNode.LastRequestTime)
		dbNodes = append(dbNodes, dbNode)
	}
	return dbNodes
}

// CreateTableIfNotExistsNodes ...
func (dal *MyDAL) CreateTableIfNotExistsNodes() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsNodes)
	return err
}

// InsertNode ...
func (dal *MyDAL) InsertNode(version string, lastIP string, lastReqTime int64) (newID int64) {
	err := dal.db.QueryRow(sqlInsertNode, version, lastIP, lastReqTime).Scan(&newID)
	utils.CheckError("InsertNode", err)
	return newID
}

// UpdateNodeLastInfo ...
func (dal *MyDAL) UpdateNodeLastInfo(version string, lastIP string, lastReqTime int64, id int64) error {
	stmt, _ := dal.db.Prepare(sqlUpdateNodeLastInfo)
	defer stmt.Close()
	_, err := stmt.Exec(version, lastIP, lastReqTime, id)
	utils.CheckError("UpdateNodeLastInfo", err)
	return err
}
