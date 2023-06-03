/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-04-01 10:48:41
 */

package models

// APIRequest used for gateway administration
type APIRequest struct {
	AuthKey  string `json:"auth_key"`
	Action   string `json:"action"`
	ObjectID int64  `json:"id,string"`
	Object   any    `json:"object"`
}

type APIApplicationRequest struct {
	Action   string       `json:"action"`
	ObjectID int64        `json:"id,string"`
	Object   *Application `json:"object"`
}

type APIVipAppRequest struct {
	Action   string  `json:"action"`
	ObjectID int64   `json:"id,string"`
	Object   *VipApp `json:"object"`
}

type APICertRequest struct {
	Action   string    `json:"action"`
	ObjectID int64     `json:"id,string"`
	Object   *CertItem `json:"object"`
}

type APIAppUserRequest struct {
	Action   string        `json:"action"`
	ObjectID int64         `json:"id,string"`
	Object   *FrontAppUser `json:"object"`
}

type APICookieRequest struct {
	Action   string  `json:"action"`
	ObjectID int64   `json:"id,string"`
	Object   *Cookie `json:"object"`
}

type APICookieRefRequest struct {
	Action   string     `json:"action"`
	ObjectID int64      `json:"id,string"`
	Object   *CookieRef `json:"object"`
}
