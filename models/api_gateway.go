/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-04-02 21:32:15
 */

package models

type APIStatByAppIDRequest struct {
	Action string `json:"action"`
	AppID  int64  `json:"app_id,string"`
	Host   string `json:"host"`
}

type APIWxworkConfigRequest struct {
	Action string        `json:"action"`
	Object *WxworkConfig `json:"object"`
}

type APIDingtalkConfigRequest struct {
	Action string          `json:"action"`
	Object *DingtalkConfig `json:"object"`
}

type APIFeishuConfigRequest struct {
	Action string        `json:"action"`
	Object *FeishuConfig `json:"object"`
}

type APILarkConfigRequest struct {
	Action string      `json:"action"`
	Object *LarkConfig `json:"object"`
}

type APILDAPConfigRequest struct {
	Action string      `json:"action"`
	Object *LDAPConfig `json:"object"`
}

type APICAS2ConfigRequest struct {
	Action string      `json:"action"`
	Object *CAS2Config `json:"object"`
}

type APIDiscoveryRuleRequest struct {
	Action string         `json:"action"`
	Object *DiscoveryRule `json:"object"`
}
