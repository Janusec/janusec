/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:27
 * @Last Modified: U2, 2018-07-14 16:31:27
 */

package data

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"../models"
	"../utils"
)

func GenAuthKey() string {
	node_auth := models.NodeAuth{NodeID: CFG.NodeID, CurTime: time.Now().Unix()}
	node_auth_bytes, err := json.Marshal(node_auth)
	utils.CheckError("GenAuthKey", err)
	encrypted_auth_bytes := EncryptWithKey(node_auth_bytes, NodeKey)
	return hex.EncodeToString(encrypted_auth_bytes)
}

func GetResponse(rpc_req *models.RPCRequest) (resp_bytes []byte, err error) {
	rpc_req.ObjectID = 0
	rpc_req.NodeID = CFG.NodeID
	rpc_req.NodeVersion = Version
	rpc_req.AuthKey = GenAuthKey()
	bytesData, err := json.Marshal(rpc_req)
	utils.CheckError("GetResponse Marshal", err)
	reader := bytes.NewReader(bytesData)
	request, err := http.NewRequest("POST", CFG.SlaveNode.SyncAddr, reader)
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	client := http.Client{}
	resp, err := client.Do(request)
	utils.CheckError("GetResponse Do", err)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	resp_bytes, err = ioutil.ReadAll(resp.Body)
	return resp_bytes, err

}
