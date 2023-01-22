/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:35
 * @Last Modified: U2, 2018-07-14 16:24:35
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// UpdateDestinationNode ...
func (dal *MyDAL) UpdateDestinationNode(routeType int64, requestRoute string, backendRoute string, destination string, podsAPI string, podPort string, appID int64, nodeID int64, id int64) error {
	const sqlUpdateDestinationNode = `UPDATE "destinations" SET "route_type"=$1,"request_route"=$2,"backend_route"=$3,"destination"=$4,"pods_api"=$5,"pod_port"=$6,"app_id"=$7,"node_id"=$8 WHERE "id"=$9`
	stmt, _ := dal.db.Prepare(sqlUpdateDestinationNode)
	defer stmt.Close()
	_, err := stmt.Exec(routeType, requestRoute, backendRoute, destination, podsAPI, podPort, appID, nodeID, id)
	if err != nil {
		utils.DebugPrintln("UpdateDestinationNode", err)
	}
	return err
}

// ExistsDestinationID ...
func (dal *MyDAL) ExistsDestinationID(id int64) bool {
	var exist int
	const sqlExistsDestinationID = `SELECT COALESCE((SELECT 1 FROM "destinations" WHERE "id"=$1 limit 1),0)`
	err := dal.db.QueryRow(sqlExistsDestinationID, id).Scan(&exist)
	if err != nil {
		utils.DebugPrintln("ExistsDestinationID", err)
	}
	return exist != 0
}

// CreateTableIfNotExistsDestinations ...
func (dal *MyDAL) CreateTableIfNotExistsDestinations() error {
	const sqlCreateTableIfNotExistsDestinations = `CREATE TABLE IF NOT EXISTS "destinations"("id" bigserial PRIMARY KEY,"route_type" bigint default 1,"request_route" VARCHAR(128) NOT NULL DEFAULT '/',"backend_route" VARCHAR(128) NOT NULL DEFAULT '/',"destination" VARCHAR(128),"pods_api" VARCHAR(512),"pod_port" VARCHAR(128),"pods" VARCHAR(1024),"app_id" bigint NOT NULL,"node_id" bigint NOT NULL)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDestinations)
	if err != nil {
		utils.DebugPrintln("CreateTableIfNotExistsDestinations", err)
	}
	return err
}

// SelectDestinationsByAppID ...
func (dal *MyDAL) SelectDestinationsByAppID(appID int64) []*models.Destination {
	dests := []*models.Destination{}
	const sqlSelectDestinationsByAppID = `SELECT "id","route_type","request_route","backend_route","destination","pods_api","pod_port","node_id" FROM "destinations" WHERE "app_id"=$1`
	rows, err := dal.db.Query(sqlSelectDestinationsByAppID, appID)
	if err != nil {
		utils.DebugPrintln("SelectDestinationsByAppID", err)
		return dests
	}
	defer rows.Close()
	for rows.Next() {
		dest := &models.Destination{AppID: appID, Online: true}
		err = rows.Scan(&dest.ID, &dest.RouteType, &dest.RequestRoute, &dest.BackendRoute, &dest.Destination, &dest.PodsAPI, &dest.PodPort, &dest.NodeID)
		if err != nil {
			utils.DebugPrintln("SelectDestinationsByAppID rows.Scan", err)
		}
		dests = append(dests, dest)
	}
	return dests
}

// InsertDestination ...
func (dal *MyDAL) InsertDestination(routeType int64, requestRoute string, backendRoute string, dest string, podsAPI string, podPort string, appID int64, nodeID int64) (newID int64, err error) {
	const sqlInsertDestination = `INSERT INTO "destinations"("route_type","request_route","backend_route","destination","pods_api","pod_port","app_id","node_id") VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING "id"`
	err = dal.db.QueryRow(sqlInsertDestination, routeType, requestRoute, backendRoute, dest, podsAPI, podPort, appID, nodeID).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertDestination", err)
	}
	return newID, err
}

// DeleteDestinationByID ...
func (dal *MyDAL) DeleteDestinationByID(id int64) error {
	const sqlDeleteDestinationByID = `DELETE FROM "destinations" WHERE "id"=$1`
	stmt, _ := dal.db.Prepare(sqlDeleteDestinationByID)
	defer stmt.Close()
	_, err := stmt.Exec(id)
	if err != nil {
		utils.DebugPrintln("DeleteDestinationByID", err)
	}
	return err
}

// DeleteDestinationsByAppID ...
func (dal *MyDAL) DeleteDestinationsByAppID(appID int64) error {
	const sqlDeleteDestinationsByAppID = `DELETE FROM "destinations" WHERE "app_id"=$1`
	stmt, _ := dal.db.Prepare(sqlDeleteDestinationsByAppID)
	defer stmt.Close()
	_, err := stmt.Exec(appID)
	if err != nil {
		utils.DebugPrintln("DeleteDestinationsByAppID", err)
	}
	return err
}
