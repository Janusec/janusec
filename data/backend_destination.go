/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:35
 * @Last Modified: U2, 2018-07-14 16:24:35
 */

package data

import (
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

const (
	sqlCreateTableIfNotExistsDestinations = `CREATE TABLE IF NOT EXISTS destinations(id bigserial PRIMARY KEY,destination varchar(128) NOT NULL,app_id bigint NOT NULL,node_id bigint NOT NULL)`
	sqlSelectDestinationsByAppID          = `SELECT id,destination,node_id FROM destinations WHERE app_id=$1`
	sqlDeleteDestinationByID              = `DELETE FROM destinations WHERE id=$1`
	sqlDeleteDestinationsByAppID          = `DELETE FROM destinations WHERE app_id=$1`
	sqlInsertDestination                  = `INSERT INTO destinations(destination,app_id,node_id) VALUES($1,$2,$3) RETURNING id`
	sqlUpdateDestinationNode              = `UPDATE destinations SET destination=$1,app_id=$2,node_id=$3 WHERE id=$4`
	sqlExistsDestinationID                = `SELECT coalesce((SELECT 1 FROM destinations WHERE id=$1 limit 1),0)`
)

func (dal *MyDAL) UpdateDestinationNode(destination string, app_id int64, node_id int64, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateDestinationNode)
	defer stmt.Close()
	_, err = stmt.Exec(destination, app_id, node_id, id)
	utils.CheckError("UpdateDestinationNode", err)
	return err
}

func (dal *MyDAL) ExistsDestinationID(id int64) bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsDestinationID, id).Scan(&exist)
	utils.CheckError("ExistsDestinationID", err)
	if exist == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) CreateTableIfNotExistsDestinations() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDestinations)
	return err
}

func (dal *MyDAL) SelectDestinationsByAppID(app_id int64) (dests []*models.Destination) {
	rows, err := dal.db.Query(sqlSelectDestinationsByAppID, app_id)
	utils.CheckError("SelectDestinationsByAppID", err)
	if err != nil {
		return dests
	}
	defer rows.Close()
	for rows.Next() {
		dest := &models.Destination{AppID: app_id}
		rows.Scan(&dest.ID, &dest.Destination, &dest.NodeID)
		dests = append(dests, dest)
	}
	return dests
}

func (dal *MyDAL) InsertDestination(dest string, app_id int64, node_id int64) (new_id int64, err error) {
	err = dal.db.QueryRow(sqlInsertDestination, dest, app_id, node_id).Scan(&new_id)
	utils.CheckError("InsertDestination", err)
	return new_id, err
}

func (dal *MyDAL) DeleteDestinationByID(id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDestinationByID)
	defer stmt.Close()
	_, err = stmt.Exec(id)
	utils.CheckError("DeleteDestinationByID", err)
	return err
}

func (dal *MyDAL) DeleteDestinationsByAppID(app_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteDestinationsByAppID)
	defer stmt.Close()
	_, err = stmt.Exec(app_id)
	utils.CheckError("DeleteDestinationsByAppID", err)
	return err
}
