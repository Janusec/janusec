/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:15
 * @Last Modified: U2, 2018-07-14 16:39:15
 */

package models

type RPCSetGroupPolicy struct {
	Action string       `json:"action"`
	Object *GroupPolicy `json:"object"`
}
