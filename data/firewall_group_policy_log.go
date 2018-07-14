/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:30:58
 * @Last Modified: U2, 2018-07-14 16:30:58
 */

package data

import (
	"../models"
	"../utils"
)

const (
	sqlCreateTableIfNotExistsGroupHitLog  = `CREATE TABLE IF NOT EXISTS group_hit_logs(id bigserial primary key,request_time bigint,client_ip varchar(256),host varchar(256),method varchar(16),url_path varchar(2048),url_query varchar(2048),content_type varchar(128),user_agent varchar(1024),cookies varchar(1024),raw_request varchar(16384),action bigint,policy_id bigint,vuln_id bigint,app_id bigint)`
	sqlInsertGroupHitLog                  = `INSERT INTO group_hit_logs(request_time,client_ip,host,method,url_path,url_query,content_type,user_agent,cookies,raw_request,action,policy_id,vuln_id,app_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	sqlSelectGroupHitLogByID              = `SELECT id,request_time,client_ip,host,method,url_path,url_query,content_type,user_agent,cookies,raw_request,action,policy_id,vuln_id,app_id FROM group_hit_logs WHERE id=$1`
	sqlSelectSimpleGroupHitLogs           = `SELECT id,request_time,client_ip,host,method,url_path,action,policy_id,app_id FROM group_hit_logs WHERE app_id=$1 and request_time between $2 and $3 LIMIT $4 OFFSET $5`
	sqlSelectGroupHitLogsCount            = `SELECT COUNT(1) FROM group_hit_logs WHERE app_id=$1 and request_time between $2 and $3`
	sqlSelectGroupHitLogsCountByVulnID    = `SELECT COUNT(1) FROM group_hit_logs WHERE app_id=$1 and vuln_id=$2 and request_time between $3 and $4`
	sqlSelectAllGroupHitLogsCount         = `SELECT COUNT(1) FROM group_hit_logs WHERE request_time between $1 and $2`
	sqlSelectAllGroupHitLogsCountByVulnID = `SELECT COUNT(1) FROM group_hit_logs WHERE vuln_id=$1 and request_time between $2 and $3`
	sqlSelectVulnStatByAppID              = `SELECT vuln_id,COUNT(vuln_id) FROM group_hit_logs WHERE app_id=$1 and request_time between $2 and $3 GROUP BY vuln_id`
	sqlSelectAllVulnStat                  = `SELECT vuln_id,COUNT(vuln_id) FROM group_hit_logs WHERE request_time between $1 and $2 GROUP BY vuln_id`
	sqlDeleteHitLogsBeforeTime            = `DELETE FROM group_hit_logs where request_time<$1`
)

func (dal *MyDAL) DeleteHitLogsBeforeTime(expired_time int64) error {
	_, err := dal.db.Exec(sqlDeleteHitLogsBeforeTime, expired_time)
	utils.CheckError("DeleteHitLogsBeforeTime", err)
	return err
}

func (dal *MyDAL) CreateTableIfNotExistsGroupHitLog() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsGroupHitLog)
	utils.CheckError("CreateTableIfNotExistsGroupHitLog", err)
	return err
}

func (dal *MyDAL) InsertGroupHitLog(request_time int64, client_ip string, host string, method string, url_path string, url_query string, content_type string, user_agent string, cookies string, raw_request string, action int64, policy_id int64, vuln_id int64, app_id int64) error {
	/*
		stmt, err := dal.db.Prepare(sqlInsertGroupHitLog)
		utils.CheckError("InsertGroupHitLog Prepare", err)
		defer stmt.Close()

		_, err = stmt.Exec(request_time, client_ip, host, method, url_path, url_query, content_type, user_agent, cookies, raw_request, action, policy_id, vuln_id, app_id)
	*/
	_, err := dal.db.Exec(sqlInsertGroupHitLog, request_time, client_ip, host, method, url_path, url_query, content_type, user_agent, cookies, raw_request, action, policy_id, vuln_id, app_id)
	utils.CheckError("InsertGroupHitLog Exec", err)
	return err
}

func (dal *MyDAL) SelectGroupHitLogsCount(app_id int64, start_time int64, end_time int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogsCount)
	utils.CheckError("SelectGroupHitLogsCount Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(app_id, start_time, end_time).Scan(&count)
	utils.CheckError("SelectGroupHitLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectGroupHitLogsCountByVulnID(app_id int64, vuln_id int64, start_time int64, end_time int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogsCountByVulnID)
	utils.CheckError("SelectGroupHitLogsCountByVulnID Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(app_id, vuln_id, start_time, end_time).Scan(&count)
	utils.CheckError("SelectGroupHitLogsCountByVulnID QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectAllGroupHitLogsCount(start_time int64, end_time int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllGroupHitLogsCount)
	utils.CheckError("SelectAllGroupHitLogsCount Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(start_time, end_time).Scan(&count)
	utils.CheckError("SelectAllGroupHitLogsCount QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectAllGroupHitLogsCountByVulnID(vuln_id int64, start_time int64, end_time int64) (int64, error) {
	stmt, err := dal.db.Prepare(sqlSelectAllGroupHitLogsCountByVulnID)
	utils.CheckError("SelectAllGroupHitLogsCountByVulnID Prepare", err)
	defer stmt.Close()
	var count int64
	err = stmt.QueryRow(vuln_id, start_time, end_time).Scan(&count)
	utils.CheckError("SelectAllGroupHitLogsCountByVulnID QueryRow", err)
	return count, err
}

func (dal *MyDAL) SelectGroupHitLogByID(id int64) (*models.GroupHitLog, error) {
	stmt, err := dal.db.Prepare(sqlSelectGroupHitLogByID)
	utils.CheckError("SelectGroupHitLogByID Prepare", err)
	defer stmt.Close()
	group_hit_log := new(models.GroupHitLog)
	err = stmt.QueryRow(id).Scan(&group_hit_log.ID,
		&group_hit_log.RequestTime,
		&group_hit_log.ClientIP,
		&group_hit_log.Host,
		&group_hit_log.Method,
		&group_hit_log.UrlPath,
		&group_hit_log.UrlQuery,
		&group_hit_log.ContentType,
		&group_hit_log.UserAgent,
		&group_hit_log.Cookies,
		&group_hit_log.RawRequest,
		&group_hit_log.Action,
		&group_hit_log.PolicyID,
		&group_hit_log.VulnID,
		&group_hit_log.AppID)
	utils.CheckError("SelectGroupHitLogByID QueryRow", err)
	return group_hit_log, err
}

func (dal *MyDAL) SelectGroupHitLogs(app_id int64, start_time int64, end_time int64, request_count int64, offset int64) (simple_group_hit_logs []*models.SimpleGroupHitLog) {
	stmt, err := dal.db.Prepare(sqlSelectSimpleGroupHitLogs)
	utils.CheckError("SelectGroupHitLogs Prepare", err)
	defer stmt.Close()
	rows, err := stmt.Query(app_id, start_time, end_time, request_count, offset)
	utils.CheckError("SelectGroupHitLogs Query", err)
	defer rows.Close()
	for rows.Next() {
		simple_group_hit_log := new(models.SimpleGroupHitLog)
		rows.Scan(&simple_group_hit_log.ID, &simple_group_hit_log.RequestTime, &simple_group_hit_log.ClientIP, &simple_group_hit_log.Host, &simple_group_hit_log.Method, &simple_group_hit_log.UrlPath, &simple_group_hit_log.Action, &simple_group_hit_log.PolicyID, &simple_group_hit_log.AppID)
		simple_group_hit_logs = append(simple_group_hit_logs, simple_group_hit_log)
	}
	return simple_group_hit_logs
}

func (dal *MyDAL) SelectVulnStatByAppID(app_id int64, start_time int64, end_time int64) (vulnStat []*models.VulnStat, err error) {
	stmt, err := dal.db.Prepare(sqlSelectVulnStatByAppID)
	utils.CheckError("SelectVulnStatByAppID Prepare", err)
	defer stmt.Close()
	rows, err := stmt.Query(app_id, start_time, end_time)
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

func (dal *MyDAL) SelectAllVulnStat(start_time int64, end_time int64) (vulnStat []*models.VulnStat, err error) {
	stmt, err := dal.db.Prepare(sqlSelectAllVulnStat)
	utils.CheckError("SelectAllVulnStat Prepare", err)
	defer stmt.Close()
	rows, err := stmt.Query(start_time, end_time)
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
