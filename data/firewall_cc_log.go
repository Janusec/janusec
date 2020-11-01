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
	sqlCreateTableIfNotExistsCCLog = `CREATE TABLE IF NOT EXISTS cc_logs(id bigserial primary key,request_time bigint,client_ip varchar(256),host varchar(256),method varchar(16),url_path varchar(2048),url_query varchar(2048),content_type varchar(128),user_agent varchar(1024),cookies varchar(1024),raw_request varchar(16384),action bigint,app_id bigint)`
	sqlInsertCCLog                 = `INSERT INTO cc_logs(request_time,client_ip,host,method,url_path,url_query,content_type,user_agent,cookies,raw_request,action,app_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	sqlSelectCCLogByID             = `SELECT id,request_time,client_ip,host,method,url_path,url_query,content_type,user_agent,cookies,raw_request,action,app_id FROM cc_logs WHERE id=$1`
	sqlSelectSimpleCCLogs          = `SELECT id,request_time,client_ip,host,method,url_path,action,app_id FROM cc_logs WHERE app_id=$1 and request_time between $2 and $3 LIMIT $4 OFFSET $5`
	sqlSelectCCLogsCount           = `SELECT COUNT(1) FROM cc_logs WHERE app_id=$1 and request_time between $2 and $3`
	sqlSelectAllCCLogsCount        = `SELECT COUNT(1) FROM cc_logs WHERE request_time between $1 and $2`
	sqlDeleteCCLogsBeforeTime      = `DELETE FROM cc_logs WHERE request_time<$1`
)

func (dal *MyDAL) DeleteCCLogsBeforeTime(expiredTime int64) error {
	_, err := dal.db.Exec(sqlDeleteCCLogsBeforeTime, expiredTime)
	utils.CheckError("DeleteCCLogsBeforeTime", err)
	return err
}

func (dal *MyDAL) CreateTableIfNotExistsCCLog() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCCLog)
	utils.CheckError("CreateTableIfNotExistsCCLog", err)
	return err
}

func (dal *MyDAL) InsertCCLog(requestTime int64, clientIP string, host string, method string, urlPath string, urlQuery string, contentType string, userAgent string, cookies string, rawRequest string, action int64, appID int64) error {
	_, err := dal.db.Exec(sqlInsertCCLog, requestTime, clientIP, host, method, urlPath, urlQuery, contentType, userAgent, cookies, rawRequest, action, appID)
	utils.CheckError("InsertCCLog Exec", err)
	return err
}

func (dal *MyDAL) SelectCCLogsCount(appID int64, startTime int64, endTime int64) (int64, error) {
	var count int64
	err := dal.db.QueryRow(sqlSelectCCLogsCount, appID, startTime, endTime).Scan(&count)
	utils.CheckError("SelectCCLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectAllCCLogsCount(startTime int64, endTime int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllCCLogsCount)
	utils.CheckError("SelectAllCCLogsCount Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(startTime, endTime).Scan(&count)
	utils.CheckError("SelectAllCCLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectCCLogByID(id int64) (*models.CCLog, error) {
	stmt, err := dal.db.Prepare(sqlSelectCCLogByID)
	utils.CheckError("SelectCCLogByID Prepare", err)
	defer stmt.Close()
	cc_log := &models.CCLog{}
	err = stmt.QueryRow(id).Scan(&cc_log.ID,
		&cc_log.RequestTime,
		&cc_log.ClientIP,
		&cc_log.Host,
		&cc_log.Method,
		&cc_log.UrlPath,
		&cc_log.UrlQuery,
		&cc_log.ContentType,
		&cc_log.UserAgent,
		&cc_log.Cookies,
		&cc_log.RawRequest,
		&cc_log.Action,
		&cc_log.AppID)
	utils.CheckError("SelectCCLogByID QueryRow", err)
	return cc_log, err
}

func (dal *MyDAL) SelectCCLogs(appID int64, startTime int64, endTime int64, request_count int64, offset int64) []*models.SimpleCCLog {
	simpleCCLogs := []*models.SimpleCCLog{}
	rows, err := dal.db.Query(sqlSelectSimpleCCLogs, appID, startTime, endTime, request_count, offset)
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
