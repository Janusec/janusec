/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:35:23
 * @Last Modified: U2, 2018-07-14 16:35:23
 */

package firewall

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"time"

	"../data"
	"../models"
	"../utils"
)

func InitHitLog() {
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsGroupHitLog()
	}
}

func LogGroupHitRequest(r *http.Request, app_id int64, client_ip string, policy *models.GroupPolicy) {
	request_time := time.Now().Unix()
	content_type := r.Header.Get("Content-Type")
	cookies := r.Header.Get("Cookie")
	raw_request_bytes, err := httputil.DumpRequest(r, true)
	utils.CheckError("LogGroupHitRequest DumpRequest", err)
	max_raw_size := len(raw_request_bytes)
	if max_raw_size > 16384 {
		max_raw_size = 16384
	}
	raw_request := string(raw_request_bytes[:max_raw_size])
	if data.IsMaster {
		data.DAL.InsertGroupHitLog(request_time, client_ip, r.Host, r.Method, r.URL.Path, r.URL.RawQuery, content_type, r.UserAgent(), cookies, raw_request, int64(policy.Action), policy.ID, policy.VulnID, app_id)
	} else {
		regex_hit_log := &models.GroupHitLog{
			RequestTime: request_time,
			ClientIP:    client_ip,
			Host:        r.Host,
			Method:      r.Method,
			UrlPath:     r.URL.Path,
			UrlQuery:    r.URL.RawQuery,
			ContentType: content_type,
			UserAgent:   r.UserAgent(),
			Cookies:     cookies,
			RawRequest:  raw_request,
			Action:      policy.Action,
			PolicyID:    policy.ID,
			VulnID:      policy.VulnID,
			AppID:       app_id}
		RPCGroupHitLog(regex_hit_log)
	}
}

func LogGroupHitRequestAPI(r *http.Request) error {
	var regex_hit_log_req models.RPCGroupHitLogRequest
	//b, err := ioutil.ReadAll(r.Body)
	//err = json.Unmarshal(b, &regex_hit_log_req)
	err := json.NewDecoder(r.Body).Decode(&regex_hit_log_req)
	defer r.Body.Close()
	utils.CheckError("LogGroupHitRequestAPI Decode", err)
	regex_hit_log := regex_hit_log_req.Object
	if regex_hit_log == nil {
		return errors.New("LogGroupHitRequestAPI parse body null.")
	}
	return data.DAL.InsertGroupHitLog(regex_hit_log.RequestTime, regex_hit_log.ClientIP, regex_hit_log.Host, regex_hit_log.Method, regex_hit_log.UrlPath, regex_hit_log.UrlQuery, regex_hit_log.ContentType, regex_hit_log.UserAgent, regex_hit_log.Cookies, regex_hit_log.RawRequest, int64(regex_hit_log.Action), regex_hit_log.PolicyID, regex_hit_log.VulnID, regex_hit_log.AppID)
}

func GetGroupLogCount(param map[string]interface{}) (*models.GroupHitLogsCount, error) {
	app_id := int64(param["app_id"].(float64))
	start_time := int64(param["start_time"].(float64))
	end_time := int64(param["end_time"].(float64))
	count, err := data.DAL.SelectGroupHitLogsCount(app_id, start_time, end_time)
	logs_count := &models.GroupHitLogsCount{AppID: app_id, StartTime: start_time, EndTime: end_time, Count: count}
	return logs_count, err
}

func GetVulnStat(param map[string]interface{}) (vulnStat []*models.VulnStat, err error) {
	app_id := int64(param["app_id"].(float64))
	start_time := int64(param["start_time"].(float64))
	end_time := int64(param["end_time"].(float64))
	if app_id == 0 {
		vulnStat, err = data.DAL.SelectAllVulnStat(start_time, end_time)
	} else {
		vulnStat, err = data.DAL.SelectVulnStatByAppID(app_id, start_time, end_time)
	}
	return vulnStat, err
}

func GetWeekStat(param map[string]interface{}) (weekStat []int64, err error) {
	app_id := int64(param["app_id"].(float64))
	vuln_id := int64(param["vuln_id"].(float64))
	start_time := int64(param["start_time"].(float64))
	for i := int64(0); i < 7; i++ {
		day_start_time := start_time + 86400*i
		day_end_time := day_start_time + 86400
		if app_id == 0 {
			if vuln_id == 0 {
				dayCount, err := data.DAL.SelectAllGroupHitLogsCount(day_start_time, day_end_time)
				utils.CheckError("GetWeekStat SelectAllGroupHitLogsCount", err)
				weekStat = append(weekStat, dayCount)
			} else {
				dayCount, err := data.DAL.SelectAllGroupHitLogsCountByVulnID(vuln_id, day_start_time, day_end_time)
				utils.CheckError("GetWeekStat SelectAllGroupHitLogsCountByVulnID", err)
				weekStat = append(weekStat, dayCount)
			}

		} else {
			if vuln_id == 0 {
				dayCount, err := data.DAL.SelectGroupHitLogsCount(app_id, day_start_time, day_end_time)
				utils.CheckError("GetWeekStat SelectGroupHitLogsCount", err)
				weekStat = append(weekStat, dayCount)
			} else {
				dayCount, err := data.DAL.SelectGroupHitLogsCountByVulnID(app_id, vuln_id, day_start_time, day_end_time)
				utils.CheckError("GetWeekStat SelectGroupHitLogsCountByVulnID", err)
				weekStat = append(weekStat, dayCount)
			}
		}
	}
	return weekStat, nil
}

func GetGroupLogs(param map[string]interface{}) ([]*models.SimpleGroupHitLog, error) {
	app_id := int64(param["app_id"].(float64))
	start_time := int64(param["start_time"].(float64))
	end_time := int64(param["end_time"].(float64))
	request_count := int64(param["request_count"].(float64))
	offset := int64(param["offset"].(float64))
	simple_regex_hit_logs := data.DAL.SelectGroupHitLogs(app_id, start_time, end_time, request_count, offset)
	return simple_regex_hit_logs, nil
}

func GetGroupLogByID(id int64) (*models.GroupHitLog, error) {
	regex_hit_log, err := data.DAL.SelectGroupHitLogByID(id)
	return regex_hit_log, err
}
