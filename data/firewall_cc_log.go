/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-08-12 18:19:11
 * @Last Modified: U2, 2018-08-12 18:19:11
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsCCLog = `CREATE TABLE IF NOT EXISTS "cc_logs"("id" bigserial primary key,"request_time" bigint,"client_ip" VARCHAR(256) NOT NULL,"host" VARCHAR(256) NOT NULL,"method" VARCHAR(16) NOT NULL,"url_path" VARCHAR(2048) NOT NULL,"url_query" VARCHAR(2048) NOT NULL DEFAULT '',"content_type" VARCHAR(128) NOT NULL DEFAULT '',"user_agent" VARCHAR(1024) NOT NULL DEFAULT '',"cookies" VARCHAR(1024) NOT NULL DEFAULT '',"raw_request" VARCHAR(16384) NOT NULL,"action" bigint,"app_id" bigint)`
	sqlInsertCCLog                 = `INSERT INTO "cc_logs"("id","request_time","client_ip","host","method","url_path","url_query","content_type","user_agent","cookies","raw_request","action","app_id") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	sqlSelectCCLogByID             = `SELECT "id","request_time","client_ip","host","method","url_path","url_query","content_type","user_agent","cookies","raw_request","action","app_id" FROM "cc_logs" WHERE "id"=$1`
	sqlSelectSimpleCCLogs          = `SELECT "id","request_time","client_ip","host","method","url_path","action","app_id" FROM "cc_logs" WHERE "app_id"=$1 AND "request_time" BETWEEN $2 AND $3 ORDER BY "request_time" DESC LIMIT $4 OFFSET $5`
	sqlSelectCCLogsCount           = `SELECT COUNT(1) FROM "cc_logs" WHERE "app_id"=$1 AND "request_time" BETWEEN $2 AND $3`
	sqlSelectAllCCLogsCount        = `SELECT COUNT(1) FROM "cc_logs" WHERE "request_time" BETWEEN $1 AND $2`
	sqlDeleteCCLogsBeforeTime      = `DELETE FROM "cc_logs" WHERE "request_time"<$1`
)

// DeleteCCLogsBeforeTime ...
func (dal *MyDAL) DeleteCCLogsBeforeTime(expiredTime int64) error {
	_, err := dal.db.Exec(sqlDeleteCCLogsBeforeTime, expiredTime)
	if err != nil {
		utils.DebugPrintln("DeleteCCLogsBeforeTime", err)
	}
	return err
}

// CreateTableIfNotExistsCCLog ...
func (dal *MyDAL) CreateTableIfNotExistsCCLog() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCCLog)
	if err != nil {
		utils.DebugPrintln("CreateTableIfNotExistsCCLog", err)
	}
	return err
}

// InsertCCLog ...
func (dal *MyDAL) InsertCCLog(requestTime int64, clientIP string, host string, method string, urlPath string, urlQuery string, contentType string, userAgent string, cookies string, rawRequest string, action int64, appID int64) error {
	snakeID := utils.GenSnowflakeID()
	_, err := dal.db.Exec(sqlInsertCCLog, snakeID, requestTime, clientIP, host, method, urlPath, urlQuery, contentType, userAgent, cookies, rawRequest, action, appID)
	if err != nil {
		utils.DebugPrintln("InsertCCLog Exec", err)
	}
	return err
}

// SelectCCLogsCount ...
func (dal *MyDAL) SelectCCLogsCount(appID int64, startTime int64, endTime int64) (int64, error) {
	var count int64
	err := dal.db.QueryRow(sqlSelectCCLogsCount, appID, startTime, endTime).Scan(&count)
	if err != nil {
		utils.DebugPrintln("SelectCCLogsCount QueryRow", err)
	}
	return count, err
}

// SelectAllCCLogsCount ...
func (dal *MyDAL) SelectAllCCLogsCount(startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllCCLogsCount)
	if err != nil {
		utils.DebugPrintln("SelectAllCCLogsCount Prepare", err)
	}
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(startTime, endTime).Scan(&count)
	if err != nil {
		utils.DebugPrintln("SelectAllCCLogsCount QueryRow", err)
	}
	return count, err
}

// SelectCCLogByID ...
func (dal *MyDAL) SelectCCLogByID(id int64) (*models.CCLog, error) {
	stmt, err := dal.db.Prepare(sqlSelectCCLogByID)
	if err != nil {
		utils.DebugPrintln("SelectCCLogByID Prepare", err)
	}
	defer stmt.Close()
	ccLog := &models.CCLog{}
	err = stmt.QueryRow(id).Scan(&ccLog.ID,
		&ccLog.RequestTime,
		&ccLog.ClientIP,
		&ccLog.Host,
		&ccLog.Method,
		&ccLog.UrlPath,
		&ccLog.UrlQuery,
		&ccLog.ContentType,
		&ccLog.UserAgent,
		&ccLog.Cookies,
		&ccLog.RawRequest,
		&ccLog.Action,
		&ccLog.AppID)
	utils.DebugPrintln("SelectCCLogByID QueryRow", err)
	return ccLog, err
}

// SelectCCLogs ...
func (dal *MyDAL) SelectCCLogs(appID int64, startTime int64, endTime int64, requestCount int64, offset int64) []*models.SimpleCCLog {
	simpleCCLogs := []*models.SimpleCCLog{}
	rows, err := dal.db.Query(sqlSelectSimpleCCLogs, appID, startTime, endTime, requestCount, offset)
	if err != nil {
		utils.DebugPrintln("SelectCCLogs Query", err)
	}
	defer rows.Close()
	for rows.Next() {
		simpleCCLog := &models.SimpleCCLog{}
		err = rows.Scan(&simpleCCLog.ID, &simpleCCLog.RequestTime, &simpleCCLog.ClientIP, &simpleCCLog.Host, &simpleCCLog.Method, &simpleCCLog.UrlPath, &simpleCCLog.Action, &simpleCCLog.AppID)
		if err != nil {
			utils.DebugPrintln("SelectCCLogs rows.Scan", err)
		}
		simpleCCLogs = append(simpleCCLogs, simpleCCLog)
	}
	return simpleCCLogs
}
