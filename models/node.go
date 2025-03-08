/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:09
 * @Last Modified: U2, 2018-07-14 16:39:09
 */

package models

type Node struct {
	ID              int64  `json:"id,string"`
	Version         string `json:"version"`
	LastIP          string `json:"last_ip"`
	LastRequestTime int64  `json:"last_req_time"`

	// PublicIP used for dns load balance, added v1.4.1
	PublicIP string `json:"public_ip"`
}

/*
type DBNode struct {
	ID              int64  `json:"id,string"`
	Version         string `json:"version"`
	LastIP          string `json:"last_ip"`
	LastRequestTime int64  `json:"last_req_time"`
}
*/

type AuthTime struct {
	CurTime int64 `json:"cur_time"`
}

type NodesKey struct {
	HexEncryptedKey string `json:"nodes_key"`
}
