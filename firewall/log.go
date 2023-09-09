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

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// InitHitLog ...
func InitHitLog() {
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsGroupHitLog()
		if err != nil {
			utils.DebugPrintln("InitHitLog CreateTableIfNotExistsGroupHitLog error", err)
		}
		err = data.DAL.CreateTableIfNotExistsCCLog()
		if err != nil {
			utils.DebugPrintln("InitHitLog CreateTableIfNotExistsCCLog error", err)
		}
	}
}

// LogCCRequest ...
func LogCCRequest(r *http.Request, appID int64, clientIP string, policy *models.CCPolicy) {
	requestTime := time.Now().Unix()
	contentType := r.Header.Get("Content-Type")
	cookies := r.Header.Get("Cookie")
	rawRequestBytes, err := httputil.DumpRequest(r, true)
	if err != nil {
		utils.DebugPrintln("LogGroupHitRequest DumpRequest", err)
	}
	maxRawSize := len(rawRequestBytes)
	if maxRawSize > 16384 {
		maxRawSize = 16384
	}
	if len(cookies) > 1024 {
		cookies = cookies[:1024]
	}
	rawRequest := string(rawRequestBytes[:maxRawSize])
	if data.IsPrimary {
		err = data.DAL.InsertCCLog(requestTime, clientIP, r.Host, r.Method, r.URL.Path, r.URL.RawQuery, contentType, r.UserAgent(), cookies, rawRequest, int64(policy.Action), appID)
		if err != nil {
			utils.DebugPrintln("InsertCCLog error", err)
		}
	} else {
		ccLog := &models.CCLog{
			RequestTime: requestTime,
			ClientIP:    clientIP,
			Host:        r.Host,
			Method:      r.Method,
			UrlPath:     r.URL.Path,
			UrlQuery:    r.URL.RawQuery,
			ContentType: contentType,
			UserAgent:   r.UserAgent(),
			Cookies:     cookies,
			RawRequest:  rawRequest,
			Action:      policy.Action,
			AppID:       appID}
		RPCCCLog(ccLog)
	}
}

// LogGroupHitRequest ...
func LogGroupHitRequest(r *http.Request, appID int64, clientIP string, policy *models.GroupPolicy) {
	requestTime := time.Now().Unix()
	contentType := r.Header.Get("Content-Type")
	cookies := r.Header.Get("Cookie")
	rawRequestBytes, err := httputil.DumpRequest(r, true)
	if err != nil {
		utils.DebugPrintln("LogGroupHitRequest DumpRequest", err)
	}
	maxRawSize := len(rawRequestBytes)
	if maxRawSize > 16384 {
		maxRawSize = 16384
	}
	rawRequest := string(rawRequestBytes[:maxRawSize])
	if data.IsPrimary {
		err = data.DAL.InsertGroupHitLog(requestTime, clientIP, r.Host, r.Method, r.URL.Path, r.URL.RawQuery, contentType, r.UserAgent(), cookies, rawRequest, int64(policy.Action), policy.ID, policy.VulnID, appID)
		if err != nil {
			utils.DebugPrintln("InsertGroupHitLog error", err)
		}
	} else {
		regexHitLog := &models.GroupHitLog{
			RequestTime: requestTime,
			ClientIP:    clientIP,
			Host:        r.Host,
			Method:      r.Method,
			UrlPath:     r.URL.Path,
			UrlQuery:    r.URL.RawQuery,
			ContentType: contentType,
			UserAgent:   r.UserAgent(),
			Cookies:     cookies,
			RawRequest:  rawRequest,
			Action:      policy.Action,
			PolicyID:    policy.ID,
			VulnID:      policy.VulnID,
			AppID:       appID}
		RPCGroupHitLog(regexHitLog)
	}
}

// LogCCRequestAPI ...
func LogCCRequestAPI(r *http.Request) error {
	var ccLogReq models.RPCCCLogRequest
	err := json.NewDecoder(r.Body).Decode(&ccLogReq)
	if err != nil {
		utils.DebugPrintln("LogCCRequestAPI Decode", err)
	}
	defer r.Body.Close()
	ccLog := ccLogReq.Object
	if ccLog == nil {
		return errors.New("LogCCRequestAPI parse body null")
	}
	return data.DAL.InsertCCLog(ccLog.RequestTime, ccLog.ClientIP, ccLog.Host, ccLog.Method, ccLog.UrlPath, ccLog.UrlQuery, ccLog.ContentType, ccLog.UserAgent, ccLog.Cookies, ccLog.RawRequest, int64(ccLog.Action), ccLog.AppID)
}

// LogGroupHitRequestAPI ...
func LogGroupHitRequestAPI(r *http.Request) error {
	var regexHitLogReq models.RPCGroupHitLogRequest
	err := json.NewDecoder(r.Body).Decode(&regexHitLogReq)
	if err != nil {
		utils.DebugPrintln("LogGroupHitRequestAPI Decode", err)
	}
	defer r.Body.Close()
	regexHitLog := regexHitLogReq.Object
	if regexHitLog == nil {
		return errors.New("LogGroupHitRequestAPI parse body null")
	}
	return data.DAL.InsertGroupHitLog(regexHitLog.RequestTime, regexHitLog.ClientIP, regexHitLog.Host, regexHitLog.Method, regexHitLog.UrlPath, regexHitLog.UrlQuery, regexHitLog.ContentType, regexHitLog.UserAgent, regexHitLog.Cookies, regexHitLog.RawRequest, int64(regexHitLog.Action), regexHitLog.PolicyID, regexHitLog.VulnID, regexHitLog.AppID)
}

// GetCCLogCount ...
func GetCCLogCount(body []byte) (*models.StatCount, error) {
	var apiStatCountRequest models.APIStatCountRequest
	if err := json.Unmarshal(body, &apiStatCountRequest); err != nil {
		utils.DebugPrintln("GetCCLogCount", err)
		return nil, err
	}
	var count int64
	var err error
	if apiStatCountRequest.AppID != 0 {
		count, err = data.DAL.SelectCCLogsCount(apiStatCountRequest.AppID, apiStatCountRequest.StartTime, apiStatCountRequest.EndTime)
	} else {
		count, err = data.DAL.SelectAllCCLogsCount(apiStatCountRequest.StartTime, apiStatCountRequest.EndTime)
	}
	statCount := &models.StatCount{
		AppID:     apiStatCountRequest.AppID,
		StartTime: apiStatCountRequest.StartTime,
		EndTime:   apiStatCountRequest.EndTime,
		Count:     count,
	}
	return statCount, err
}

// GetGroupLogCount ...
func GetGroupLogCount(body []byte) (*models.StatCount, error) {
	var apiStatCountRequest models.APIStatCountRequest
	if err := json.Unmarshal(body, &apiStatCountRequest); err != nil {
		utils.DebugPrintln("GetGroupLogCount", err)
		return nil, err
	}
	var count int64
	var err error
	if apiStatCountRequest.AppID != 0 {
		count, err = data.DAL.SelectGroupHitLogsCountByAppID(apiStatCountRequest.AppID, apiStatCountRequest.StartTime, apiStatCountRequest.EndTime)
	} else {
		count, err = data.DAL.SelectGroupHitLogsCount(apiStatCountRequest.StartTime, apiStatCountRequest.EndTime)
	}
	statCount := &models.StatCount{
		AppID:     apiStatCountRequest.AppID,
		StartTime: apiStatCountRequest.StartTime,
		EndTime:   apiStatCountRequest.EndTime,
		Count:     count,
	}
	return statCount, err
}

// GetVulnStat ...
func GetVulnStat(body []byte) (vulnStat []*models.VulnStat, err error) {
	var rpcStatCountRequest models.APIStatCountRequest
	if err := json.Unmarshal(body, &rpcStatCountRequest); err != nil {
		utils.DebugPrintln("GetVulnStat", err)
		return nil, err
	}
	if rpcStatCountRequest.AppID == 0 {
		vulnStat, err = data.DAL.SelectAllVulnStat(rpcStatCountRequest.StartTime, rpcStatCountRequest.EndTime)
	} else {
		vulnStat, err = data.DAL.SelectVulnStatByAppID(rpcStatCountRequest.AppID, rpcStatCountRequest.StartTime, rpcStatCountRequest.EndTime)
	}
	if err != nil {
		utils.DebugPrintln("GetVulnStat", err)
	}
	return vulnStat, err
}

// GetWeekStat ...
func GetWeekStat(body []byte) (weekStat []int64, err error) {
	var apiWeekStatRequest models.APIWeekStatRequest
	if err := json.Unmarshal(body, &apiWeekStatRequest); err != nil {
		utils.DebugPrintln("GetVulnStat", err)
		return nil, err
	}
	//stat := rpcWeekStatRequest.Object
	for i := int64(0); i < 7; i++ {
		dayStartTime := apiWeekStatRequest.StartTime + 86400*i
		dayEndTime := dayStartTime + 86400
		if apiWeekStatRequest.AppID == 0 {
			if apiWeekStatRequest.VulnID == 0 {
				dayCount, err := data.DAL.SelectAllGroupHitLogsCount(dayStartTime, dayEndTime)
				if err != nil {
					utils.DebugPrintln("GetWeekStat SelectAllGroupHitLogsCount", err)
				}
				weekStat = append(weekStat, dayCount)
			} else {
				dayCount, err := data.DAL.SelectAllGroupHitLogsCountByVulnID(apiWeekStatRequest.VulnID, dayStartTime, dayEndTime)
				if err != nil {
					utils.DebugPrintln("GetWeekStat SelectAllGroupHitLogsCountByVulnID", err)
				}
				weekStat = append(weekStat, dayCount)
			}

		} else {
			if apiWeekStatRequest.VulnID == 0 {
				dayCount, err := data.DAL.SelectGroupHitLogsCountByAppID(apiWeekStatRequest.AppID, dayStartTime, dayEndTime)
				if err != nil {
					utils.DebugPrintln("GetWeekStat SelectGroupHitLogsCount", err)
				}
				weekStat = append(weekStat, dayCount)
			} else {
				dayCount, err := data.DAL.SelectGroupHitLogsCountByVulnID(apiWeekStatRequest.AppID, apiWeekStatRequest.VulnID, dayStartTime, dayEndTime)
				if err != nil {
					utils.DebugPrintln("GetWeekStat SelectGroupHitLogsCountByVulnID", err)
				}
				weekStat = append(weekStat, dayCount)
			}
		}
	}
	return weekStat, nil
}

// GetCCLogs ...
func GetCCLogs(body []byte) ([]*models.SimpleCCLog, error) {
	var apiHitLogRequest models.APIHitLogsRequest
	if err := json.Unmarshal(body, &apiHitLogRequest); err != nil {
		utils.DebugPrintln("GetCCLogs", err)
		return nil, err
	}
	var simpleCCLogs []*models.SimpleCCLog
	if apiHitLogRequest.AppID != 0 {
		simpleCCLogs = data.DAL.SelectCCLogsByAppID(apiHitLogRequest.AppID, apiHitLogRequest.StartTime, apiHitLogRequest.EndTime, apiHitLogRequest.RequestCount, apiHitLogRequest.Offset)
	} else {
		simpleCCLogs = data.DAL.SelectCCLogs(apiHitLogRequest.StartTime, apiHitLogRequest.EndTime, apiHitLogRequest.RequestCount, apiHitLogRequest.Offset)
	}
	return simpleCCLogs, nil
}

// GetGroupLogs ...
func GetGroupLogs(body []byte) ([]*models.SimpleGroupHitLog, error) {
	var apiHitLogRequest models.APIHitLogsRequest
	if err := json.Unmarshal(body, &apiHitLogRequest); err != nil {
		utils.DebugPrintln("GetGroupLogs", err)
		return nil, err
	}
	var simpleRegexHitLogs []*models.SimpleGroupHitLog
	if apiHitLogRequest.AppID != 0 {
		simpleRegexHitLogs = data.DAL.SelectGroupHitLogsByAppID(apiHitLogRequest.AppID, apiHitLogRequest.StartTime, apiHitLogRequest.EndTime, apiHitLogRequest.RequestCount, apiHitLogRequest.Offset)
	} else {
		// all applications
		simpleRegexHitLogs = data.DAL.SelectGroupHitLogs(apiHitLogRequest.StartTime, apiHitLogRequest.EndTime, apiHitLogRequest.RequestCount, apiHitLogRequest.Offset)
	}
	return simpleRegexHitLogs, nil
}

// GetGroupLogByID ...
func GetGroupLogByID(id int64) (*models.GroupHitLog, error) {
	regexHitLog, err := data.DAL.SelectGroupHitLogByID(id)
	return regexHitLog, err
}

// GetCCLogByID ...
func GetCCLogByID(id int64) (*models.CCLog, error) {
	ccLog, err := data.DAL.SelectCCLogByID(id)
	return ccLog, err
}
