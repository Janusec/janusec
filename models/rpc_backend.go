/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-04-01 10:48:41
 */

package models

type RPCApplicationRequest struct {
	Action   string       `json:"action"`
	ObjectID int64        `json:"id,string"`
	Object   *Application `json:"object"`
}

type RPCVipAppRequest struct {
	Action   string  `json:"action"`
	ObjectID int64   `json:"id,string"`
	Object   *VipApp `json:"object"`
}
