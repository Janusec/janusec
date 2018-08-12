/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:56
 * @Last Modified: U2, 2018-07-14 16:38:56
 */

package models

import (
	"time"
)

type PolicyAction int64

const (
	Action_Block_100        PolicyAction = 100
	Action_BypassAndLog_200 PolicyAction = 200
	Action_CAPTCHA_300      PolicyAction = 300
	Action_Pass_400         PolicyAction = 400
)

type CCPolicy struct {
	AppID           int64         `json:"app_id"` // Global Policy set app_id=0
	IntervalSeconds time.Duration `json:"interval_seconds"`
	MaxCount        int64         `json:"max_count"`
	BlockSeconds    time.Duration `json:"block_seconds"`
	Action          PolicyAction  `json:"action"`
	StatByURL       bool          `json:"stat_by_url"`
	StatByUserAgent bool          `json:"stat_by_ua"`
	StatByCookie    bool          `json:"stat_by_cookie"`
	IsEnabled       bool          `json:"is_enabled"`
}

type ChkPoint int64

const (
	ChkPointHost                ChkPoint = 1
	ChkPointIPAddress           ChkPoint = 1 << 1
	ChkPointMethod              ChkPoint = 1 << 2
	ChkPointURLPath             ChkPoint = 1 << 3
	ChkPointURLQuery            ChkPoint = 1 << 4
	ChkPointValueLength         ChkPoint = 1 << 6
	ChkPointGetPostKey          ChkPoint = 1 << 7
	ChkPointGetPostValue        ChkPoint = 1 << 8
	ChkPointUploadFileExt       ChkPoint = 1 << 9
	ChkPointCookieKey           ChkPoint = 1 << 11
	ChkPointCookieValue         ChkPoint = 1 << 12
	ChkPointUserAgent           ChkPoint = 1 << 13
	ChkPointContentType         ChkPoint = 1 << 14
	ChkPointHeaderKey           ChkPoint = 1 << 15
	ChkPointHeaderValue         ChkPoint = 1 << 16
	ChkPointProto               ChkPoint = 1 << 17
	ChkPointResponseStatusCode  ChkPoint = 1 << 25
	ChkPointResponseHeaderKey   ChkPoint = 1 << 26
	ChkPointResponseHeaderValue ChkPoint = 1 << 27
	ChkPointResponseBodyLength  ChkPoint = 1 << 28
	ChkPointResponseBody        ChkPoint = 1 << 29
)

type GroupPolicy struct {
	ID          int64        `json:"id"`
	Description string       `json:"description"`
	AppID       int64        `json:"app_id"`
	VulnID      int64        `json:"vuln_id"`
	CheckItems  []*CheckItem `json:"check_items"`
	HitValue    int64        `json:"hit_value"`
	Action      PolicyAction `json:"action"`
	IsEnabled   bool         `json:"is_enabled"`
	UserID      int64        `json:"user_id"`
	User        *AppUser     `json:"-"`
	UpdateTime  int64        `json:"update_time"`
}

/*
type DBGroupPolicy struct {
	ID          int64        `json:"id"`
	Description string       `json:"description"`
	AppID       int64        `json:"app_id"`
	VulnID      int64        `json:"vuln_id"`
	HitValue    int64        `json:"hit_value"`
	Action      PolicyAction `json:"action"`
	IsEnabled   bool         `json:"is_enabled"`
	UserID      int64        `json:"user_id"`
	UpdateTime  int64        `json:"update_time"`
}
*/

type Operation int64

const (
	OperationRegexMatch                  Operation = 1
	OperationEqualsStringCaseInSensitive Operation = 1 << 1
	OperationGreaterThanInteger          Operation = 1 << 2
	OperationEqualsInteger               Operation = 1 << 3
)

type CheckItem struct {
	ID            int64        `json:"id"`
	CheckPoint    ChkPoint     `json:"check_point"`
	Operation     Operation    `json:"operation"`
	KeyName       string       `json:"key_name"`
	RegexPolicy   string       `json:"regex_policy"`
	GroupPolicyID int64        `json:"group_policy_id"`
	GroupPolicy   *GroupPolicy `json:"-"`
}

/*
type DBCheckItem struct {
	ID            int64    `json:"id"`
	CheckPoint    ChkPoint `json:"check_point"`
	KeyName       string   `json:"key_name"`
	RegexPolicy   string   `json:"regex_policy"`
	GroupPolicyID int64    `json:"group_policy_id"`
}
*/

type ClientStat struct {
	Count         int64
	IsBlackIP     bool
	RemainSeconds time.Duration
}

type VulnType struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type RegexMatch struct {
	Pattern    string `json:"pattern"`
	Payload    string `json:"payload"`
	Matched    bool   `json:"matched"`
	PreProcess bool   `json:"preprocess"`
}

type CCLog struct {
	ID          int64        `json:"id"`
	RequestTime int64        `json:"request_time"`
	ClientIP    string       `json:"client_ip"`
	Host        string       `json:"host"`
	Method      string       `json:"method"`
	UrlPath     string       `json:"url_path"`
	UrlQuery    string       `json:"url_query"`
	ContentType string       `json:"content_type"`
	UserAgent   string       `json:"user_agent"`
	Cookies     string       `json:"cookies"`
	RawRequest  string       `json:"raw_request"`
	Action      PolicyAction `json:"action"`
	AppID       int64        `json:"app_id"`
}

type SimpleCCLog struct {
	ID          int64        `json:"id"`
	RequestTime int64        `json:"request_time"`
	ClientIP    string       `json:"client_ip"`
	Host        string       `json:"host"`
	Method      string       `json:"method"`
	UrlPath     string       `json:"url_path"`
	Action      PolicyAction `json:"action"`
	AppID       int64        `json:"app_id"`
}

type GroupHitLog struct {
	ID          int64        `json:"id"`
	RequestTime int64        `json:"request_time"`
	ClientIP    string       `json:"client_ip"`
	Host        string       `json:"host"`
	Method      string       `json:"method"`
	UrlPath     string       `json:"url_path"`
	UrlQuery    string       `json:"url_query"`
	ContentType string       `json:"content_type"`
	UserAgent   string       `json:"user_agent"`
	Cookies     string       `json:"cookies"`
	RawRequest  string       `json:"raw_request"`
	Action      PolicyAction `json:"action"`
	PolicyID    int64        `json:"policy_id"`
	VulnID      int64        `json:"vuln_id"`
	AppID       int64        `json:"app_id"`
}

type SimpleGroupHitLog struct {
	ID          int64        `json:"id"`
	RequestTime int64        `json:"request_time"`
	ClientIP    string       `json:"client_ip"`
	Host        string       `json:"host"`
	Method      string       `json:"method"`
	UrlPath     string       `json:"url_path"`
	Action      PolicyAction `json:"action"`
	PolicyID    int64        `json:"policy_id"`
	AppID       int64        `json:"app_id"`
}

type HitLogsCount struct {
	AppID     int64 `json:"app_id"`
	StartTime int64 `json:"start_time"`
	EndTime   int64 `json:"end_time"`
	Count     int64 `json:"count"`
}

type VulnStat struct {
	VulnID int64 `json:"vuln_id"`
	Count  int64 `json:"count"`
}
