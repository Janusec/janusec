/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:23
 * @Last Modified: U2, 2018-07-14 16:39:23
 */

package models

type RPCResponse struct {
	Error  *string     `json:"err"`
	Object interface{} `json:"object"`
}

type RPCRequest struct {
	Action      string      `json:"action"`
	ObjectID    int64       `json:"id,string"`
	NodeVersion string      `json:"node_version"`
	AuthKey     string      `json:"auth_key"`
	Object      interface{} `json:"object"`

	// PublicIP used for dns load balance, added v1.4.1
	PublicIP string `json:"public_ip"`
}

type RPCGroupHitLogRequest struct {
	Action   string       `json:"action"`
	ObjectID int64        `json:"id,string"`
	NodeID   int64        `json:"node_id,string"`
	AuthKey  string       `json:"auth_key"`
	Object   *GroupHitLog `json:"object"`
}

type RPCCCLogRequest struct {
	Action   string `json:"action"`
	ObjectID int64  `json:"id,string"`
	NodeID   int64  `json:"node_id,string"`
	AuthKey  string `json:"auth_key"`
	Object   *CCLog `json:"object"`
}

type RPCCertItems struct {
	Error  *string     `json:"err"`
	Object []*CertItem `json:"object"`
}

type RPCApplications struct {
	Error  *string        `json:"err"`
	Object []*Application `json:"object"`
}

type RPCVipApps struct {
	Error  *string   `json:"err"`
	Object []*VipApp `json:"object"`
}

type RPCDBDomains struct {
	Error  *string     `json:"err"`
	Object []*DBDomain `json:"object"`
}

type RPCCCPolicies struct {
	Error  *string     `json:"err"`
	Object []*CCPolicy `json:"object"`
}

type RPCGroupPolicies struct {
	Error  *string        `json:"err"`
	Object []*GroupPolicy `json:"object"`
}

type RPCVulntypes struct {
	Error  *string     `json:"err"`
	Object []*VulnType `json:"object"`
}

/*
type RPCSettings struct {
	Error  *string    `json:"err"`
	Object []*Setting `json:"object"`
}
*/

type RPCOAuthConfig struct {
	Error  *string      `json:"err"`
	Object *OAuthConfig `json:"object"`
}

type RPCTOTP struct {
	Error  *string `json:"err"`
	Object *TOTP   `json:"object"`
}

type RPCStatRequest struct {
	Action   string        `json:"action"`
	ObjectID int64         `json:"id,string"`
	NodeID   int64         `json:"node_id,string"`
	AuthKey  string        `json:"auth_key"`
	Object   []*AccessStat `json:"object"`
}

type RPCRefererRequest struct {
	Action   string                                            `json:"action"`
	ObjectID int64                                             `json:"id,string"`
	NodeID   int64                                             `json:"node_id,string"`
	AuthKey  string                                            `json:"auth_key"`
	Object   *map[int64]map[string]map[string]map[string]int64 `json:"object"`
}

type RPCNodeSetting struct {
	Error  *string           `json:"err"`
	Object *NodeShareSetting `json:"object"`
}

// PrimarySettingRequest for update NodeSetting
type PrimarySettingRequest struct {
	Action string          `json:"action"`
	Object *PrimarySetting `json:"object"`
}

type RPCDiscoveryRules struct {
	Error  *string          `json:"err"`
	Object []*DiscoveryRule `json:"object"`
}

type RPCCookieRefs struct {
	Error  *string      `json:"err"`
	Object []*CookieRef `json:"object"`
}
