/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-07 09:43:07
 * @Last Modified: U2, 2020-10-07 09:43:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsAccessStats create statistics table
func (dal *MyDAL) CreateTableIfNotExistsAccessStats() error {
	const sqlCreateTableIfNotExistsStats = `CREATE TABLE IF NOT EXISTS access_stats(id bigserial PRIMARY KEY, app_id bigint, url_path varchar(256), stat_date varchar(16), amount bigint, update_time bigint)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsStats)
	return err
}

// IncAmount update access statistics
func (dal *MyDAL) IncAmount(appID int64, urlPath string, statDate string, delta int64, updateTime int64) error {
	var id, amount int64
	const sql = `select id,amount from access_stats where app_id=$1 and url_path=$2 and stat_date=$3 LIMIT 1`
	err := dal.db.QueryRow(sql, appID, urlPath, statDate).Scan(&id, &amount)
	if err != nil {
		// Not existed before
		const sqlInsert = `INSERT INTO access_stats(app_id,url_path,stat_date,amount,update_time) VALUES($1,$2,$3,$4,$5)`
		_, err = dal.db.Exec(sqlInsert, appID, urlPath, statDate, delta, updateTime)
		if err != nil {
			utils.DebugPrintln("IncAmount insert", err)
		}
		return err
	}
	const sqlUpdate = `UPDATE access_stats SET amount=$1,update_time=$2 WHERE id=$3`
	_, err = dal.db.Exec(sqlUpdate, amount+delta, updateTime, id)
	if err != nil {
		utils.DebugPrintln("IncAmount update", err)
	}
	return err
}

// ClearExpiredAccessStats clear access statistics before designated time
func (dal *MyDAL) ClearExpiredAccessStats(expiredTime int64) error {
	const sqlDel = `DELETE FROM access_stats WHERE update_time<$1`
	_, err := dal.db.Exec(sqlDel, expiredTime)
	if err != nil {
		utils.DebugPrintln("ClearExpiredAccessStats", err)
	}
	return err
}

// GetAccessStatByAppIDAndDate return the amount of designated app
func (dal *MyDAL) GetAccessStatByAppIDAndDate(appID int64, statDate string) int64 {
	amount := int64(0)
	if appID == 0 {
		const sqlQuery0 = `SELECT SUM(amount) from access_stats WHERE stat_date=$1`
		_ = dal.db.QueryRow(sqlQuery0, statDate).Scan(&amount)
		return amount
	}
	const sqlQuery1 = `SELECT SUM(amount) from access_stats WHERE app_id=$1 and stat_date=$2`
	_ = dal.db.QueryRow(sqlQuery1, appID, statDate).Scan(&amount)
	return amount
}

// GetPopularContent return top visited URL Path
func (dal *MyDAL) GetPopularContent(appID int64, statDate string) ([]*models.PopularContent, error) {
	topPaths := []*models.PopularContent{}
	if appID == 0 {
		const sqlQuery0 = `SELECT app_id,url_path,amount from access_stats WHERE stat_date=$1 ORDER BY amount DESC LIMIT 100`
		rows, _ := dal.db.Query(sqlQuery0, statDate)
		for rows.Next() {
			var popContent = &models.PopularContent{}
			_ = rows.Scan(&popContent.AppID, &popContent.URLPath, &popContent.Amount)
			topPaths = append(topPaths, popContent)
		}
		return topPaths, nil
	}
	const sqlQuery1 = `SELECT app_id,url_path,amount from access_stats WHERE app_id=$1 and stat_date=$2 ORDER BY amount DESC LIMIT 100`
	rows, _ := dal.db.Query(sqlQuery1, appID, statDate)
	for rows.Next() {
		var popContent = &models.PopularContent{}
		_ = rows.Scan(&popContent.AppID, &popContent.URLPath, &popContent.Amount)
		topPaths = append(topPaths, popContent)
	}
	return topPaths, nil
}
