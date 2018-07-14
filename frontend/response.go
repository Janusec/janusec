/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:40
 * @Last Modified: U2, 2018-07-14 16:36:40
 */

package frontend

import (
	"encoding/json"
	"net/http"

	"../models"
)

func GenResponseByObject(w http.ResponseWriter, object interface{}, err error) {
	resp := new(models.RPCResponse)
	if err == nil {
		resp.Error = nil
	} else {
		err_str := err.Error()
		resp.Error = &err_str
	}
	resp.Object = object
	json.NewEncoder(w).Encode(resp)
}
