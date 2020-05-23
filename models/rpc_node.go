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
	ObjectID    int64       `json:"id"`
	NodeVersion string      `json:"node_version"`
	AuthKey     string      `json:"auth_key"`
	Object      interface{} `json:"object"`
}

type RPCGroupHitLogRequest struct {
	Action   string       `json:"action"`
	ObjectID int64        `json:"id"`
	NodeID   int64        `json:"node_id"`
	AuthKey  string       `json:"auth_key"`
	Object   *GroupHitLog `json:"object"`
}

type RPCCCLogRequest struct {
	Action   string `json:"action"`
	ObjectID int64  `json:"id"`
	NodeID   int64  `json:"node_id"`
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

type RPCSettings struct {
	Error  *string    `json:"err"`
	Object []*Setting `json:"object"`
}

type RPCOAuthConfig struct {
	Error  *string      `json:"err"`
	Object *OAuthConfig `json:"object"`
}

type RPCTOTP struct {
	Error  *string `json:"err"`
	Object *TOTP   `json:"object"`
}
