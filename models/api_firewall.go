/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:15
 * @Last Modified: U2, 2018-07-14 16:39:15
 */

package models

type APIGroupPolicyRequest struct {
	Action string       `json:"action"`
	Object *GroupPolicy `json:"object"`
}

type APICCPolicyRequest struct {
	Action string    `json:"action"`
	Object *CCPolicy `json:"object"`
}

type APIIPPolicyRequest struct {
	Action string    `json:"action"`
	Object *IPPolicy `json:"object"`
}

// APIRegexMatchRequest for Regex Match Test
type APIRegexMatchRequest struct {
	Action string      `json:"action"`
	Object *RegexMatch `json:"object"`
}

type APIStatCountRequest struct {
	Action    string `json:"action"`
	AppID     int64  `json:"app_id,string"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
	Count     int64  `json:"count"`
}

type HitLogsRequest struct {
	AppID        int64 `json:"app_id"`
	StartTime    int64 `json:"start_time"`
	EndTime      int64 `json:"end_time"`
	RequestCount int64 `json:"request_count"`
	Offset       int64 `json:"offset"`
}

type APIHitLogsRequest struct {
	Action string          `json:"action"`
	Object *HitLogsRequest `json:"object"`
}

/*
type WeekStat struct {
	AppID     int64 `json:"app_id,string"`
	VulnID    int64 `json:"vuln_id"`
	StartTime int64 `json:"start_time"`
}
*/

type APIWeekStatRequest struct {
	Action    string `json:"action"`
	AppID     int64  `json:"app_id,string"`
	VulnID    int64  `json:"vuln_id"`
	StartTime int64  `json:"start_time"`
}
