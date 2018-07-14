/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:09
 * @Last Modified: U2, 2018-07-14 16:39:09
 */

package models

type NodeAuth struct {
	NodeID  int64 `json:"node_id"`
	CurTime int64 `json:"cur_time"`
}
