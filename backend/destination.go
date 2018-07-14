/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:54
 * @Last Modified: U2, 2018-07-14 16:21:54
 */

package backend

//"../models"

func InterfaceContainsDestinationID(destinations []interface{}, dest_id int64) bool {
	for _, destination := range destinations {
		destMap := destination.(map[string]interface{})
		id := int64(destMap["id"].(float64))
		if id == dest_id {
			return true
		}
	}
	return false
}
