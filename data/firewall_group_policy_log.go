/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:30:58
 * @Last Modified: U2, 2018-07-14 16:30:58
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsGroupHitLog  = `CREATE TABLE IF NOT EXISTS "group_hit_logs"("id" bigserial primary key,"request_time" bigint,"client_ip" VARCHAR(256) NOT NULL,"host" VARCHAR(256) NOT NULL,"method" VARCHAR(16) NOT NULL,"url_path" VARCHAR(2048) NOT NULL,"url_query" VARCHAR(2048) NOT NULL DEFAULT '',"content_type" VARCHAR(128) NOT NULL DEFAULT '',"user_agent" VARCHAR(1024) NOT NULL DEFAULT '',"cookies" VARCHAR(1024) NOT NULL DEFAULT '',"raw_request" VARCHAR(16384) NOT NULL,"action" bigint,"policy_id" bigint,"vuln_id" bigint,"app_id" bigint)`
	sqlInsertGroupHitLog                  = `INSERT INTO "group_hit_logs"("request_time","client_ip","host","method","url_path","url_query","content_type","user_agent","cookies","raw_request","action","policy_id","vuln_id","app_id") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	sqlSelectGroupHitLogByID              = `SELECT "id","request_time","client_ip","host","method","url_path","url_query","content_type","user_agent","cookies","raw_request","action","policy_id","vuln_id","app_id" FROM "group_hit_logs" WHERE "id"=$1`
	sqlSelectSimpleGroupHitLogs           = `SELECT "id","request_time","client_ip","host","method","url_path","action","policy_id","app_id" FROM "group_hit_logs" WHERE "app_id"=$1 AND "request_time" BETWEEN $2 AND $3 LIMIT $4 OFFSET $5`
	sqlSelectGroupHitLogsCount            = `SELECT COUNT(1) FROM "group_hit_logs" WHERE "app_id"=$1 AND request_time BETWEEN $2 AND $3`
	sqlSelectGroupHitLogsCountByVulnID    = `SELECT COUNT(1) FROM "group_hit_logs" WHERE "app_id"=$1 AND "vuln_id"=$2 AND "request_time" BETWEEN $3 AND $4`
	sqlSelectAllGroupHitLogsCount         = `SELECT COUNT(1) FROM "group_hit_logs" WHERE "request_time" BETWEEN $1 AND $2`
	sqlSelectAllGroupHitLogsCountByVulnID = `SELECT COUNT(1) FROM "group_hit_logs" WHERE "vuln_id"=$1 AND "request_time" BETWEEN $2 AND $3`
	sqlSelectVulnStatByAppID              = `SELECT "vuln_id",COUNT("vuln_id") FROM "group_hit_logs" WHERE "app_id"=$1 AND "request_time" BETWEEN $2 AND $3 GROUP BY "vuln_id"`
	sqlSelectAllVulnStat                  = `SELECT "vuln_id",COUNT("vuln_id") FROM "group_hit_logs" WHERE "request_time" BETWEEN $1 AND $2 GROUP BY "vuln_id"`
	sqlDeleteHitLogsBeforeTime            = `DELETE FROM "group_hit_logs" where "request_time"<$1`
)

func (dal *MyDAL) DeleteHitLogsBeforeTime(expiredTime int64) error {
	_, err := dal.db.Exec(sqlDeleteHitLogsBeforeTime, expiredTime)
	utils.CheckError("DeleteHitLogsBeforeTime", err)
	return err
}

func (dal *MyDAL) CreateTableIfNotExistsGroupHitLog() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsGroupHitLog)
	utils.CheckError("CreateTableIfNotExistsGroupHitLog", err)
	return err
}

func (dal *MyDAL) InsertGroupHitLog(requestTime int64, clientIP string, host string, method string, urlPath string, urlQuery string, contentType string, userAgent string, cookies string, rawRequest string, action int64, policyID int64, vulnID int64, appID int64) error {
	_, err := dal.db.Exec(sqlInsertGroupHitLog, requestTime, clientIP, host, method, urlPath, urlQuery, contentType, userAgent, cookies, rawRequest, action, policyID, vulnID, appID)
	utils.CheckError("InsertGroupHitLog Exec", err)
	return err
}

func (dal *MyDAL) SelectGroupHitLogsCount(appID int64, startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogsCount)
	utils.CheckError("SelectGroupHitLogsCount Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(appID, startTime, endTime).Scan(&count)
	utils.CheckError("SelectGroupHitLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectGroupHitLogsCountByVulnID(appID int64, vulnID int64, startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogsCountByVulnID)
	utils.CheckError("SelectGroupHitLogsCountByVulnID Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(appID, vulnID, startTime, endTime).Scan(&count)
	utils.CheckError("SelectGroupHitLogsCountByVulnID QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectAllGroupHitLogsCount(startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllGroupHitLogsCount)
	utils.CheckError("SelectAllGroupHitLogsCount Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(startTime, endTime).Scan(&count)
	utils.CheckError("SelectAllGroupHitLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectAllGroupHitLogsCountByVulnID(vulnID int64, startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllGroupHitLogsCountByVulnID)
	utils.CheckError("SelectAllGroupHitLogsCountByVulnID Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(vulnID, startTime, endTime).Scan(&count)
	utils.CheckError("SelectAllGroupHitLogsCountByVulnID QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectGroupHitLogByID(id int64) (*models.GroupHitLog, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogByID)
	utils.CheckError("SelectGroupHitLogByID Prepare", err)
	defer stmt.Close()
	groupHitLog := &models.GroupHitLog{}
	err = stmt.QueryRow(id).Scan(&groupHitLog.ID,
		&groupHitLog.RequestTime,
		&groupHitLog.ClientIP,
		&groupHitLog.Host,
		&groupHitLog.Method,
		&groupHitLog.UrlPath,
		&groupHitLog.UrlQuery,
		&groupHitLog.ContentType,
		&groupHitLog.UserAgent,
		&groupHitLog.Cookies,
		&groupHitLog.RawRequest,
		&groupHitLog.Action,
		&groupHitLog.PolicyID,
		&groupHitLog.VulnID,
		&groupHitLog.AppID)
	utils.CheckError("SelectGroupHitLogByID QueryRow", err)
	return groupHitLog, err
}

func (dal *MyDAL) SelectGroupHitLogs(appID int64, startTime int64, endTime int64, request_count int64, offset int64) []*models.SimpleGroupHitLog {
	simpleGroupHitLogs := []*models.SimpleGroupHitLog{}
	stmt, err := dal.db.Prepare(sqlSelectSimpleGroupHitLogs)
	if err != nil {
		utils.DebugPrintln("SelectGroupHitLogs Prepare", err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(appID, startTime, endTime, request_count, offset)
	if err != nil {
		utils.DebugPrintln("SelectGroupHitLogs Query", err)
	}
	defer rows.Close()
	for rows.Next() {
		simpleGroupHitLog := &models.SimpleGroupHitLog{}
		err = rows.Scan(&simpleGroupHitLog.ID, &simpleGroupHitLog.RequestTime, &simpleGroupHitLog.ClientIP, &simpleGroupHitLog.Host, &simpleGroupHitLog.Method, &simpleGroupHitLog.UrlPath, &simpleGroupHitLog.Action, &simpleGroupHitLog.PolicyID, &simpleGroupHitLog.AppID)
		if err != nil {
			utils.DebugPrintln("SelectGroupHitLogs rows.Scan", err)
		}
		simpleGroupHitLogs = append(simpleGroupHitLogs, simpleGroupHitLog)
	}
	return simpleGroupHitLogs
}

func (dal *MyDAL) SelectVulnStatByAppID(appID int64, startTime int64, endTime int64) ([]*models.VulnStat, error) {
	vulnStat := []*models.VulnStat{}
	stmt, err := dal.db.Prepare(sqlSelectVulnStatByAppID)
	utils.CheckError("SelectVulnStatByAppID Prepare", err)
	defer stmt.Close()
	rows, err := stmt.Query(appID, startTime, endTime)
	utils.CheckError("SelectVulnStatByAppID Query", err)
	defer rows.Close()
	for rows.Next() {
		var vulnID, count int64
		err := rows.Scan(&vulnID, &count)
		utils.CheckError("SelectVulnStatByAppID Scan", err)
		stat := &models.VulnStat{VulnID: vulnID, Count: count}
		vulnStat = append(vulnStat, stat)
	}
	return vulnStat, err
}

func (dal *MyDAL) SelectAllVulnStat(startTime int64, endTime int64) ([]*models.VulnStat, error) {
	vulnStat := []*models.VulnStat{}
	stmt, err := dal.db.Prepare(sqlSelectAllVulnStat)
	utils.CheckError("SelectAllVulnStat Prepare", err)
	defer stmt.Close()
	rows, err := stmt.Query(startTime, endTime)
	utils.CheckError("SelectAllVulnStat Query", err)
	defer rows.Close()
	for rows.Next() {
		var vulnID, count int64
		err := rows.Scan(&vulnID, &count)
		utils.CheckError("SelectAllVulnStat Scan", err)
		stat := &models.VulnStat{VulnID: vulnID, Count: count}
		vulnStat = append(vulnStat, stat)
	}
	return vulnStat, err
}
