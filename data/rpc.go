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

	"janusec/models"
	"janusec/utils"
)

// GenAuthKey for authentication between replica nodes and primary node
func GenAuthKey() string {
	nodeAuth := models.NodeAuth{CurTime: time.Now().Unix()}
	nodeAuthBytes, err := json.Marshal(nodeAuth)
	utils.CheckError("GenAuthKey", err)
	encryptedAuthBytes := EncryptWithKey(nodeAuthBytes, RootKey)
	return hex.EncodeToString(encryptedAuthBytes)
}

// GetRPCResponse ...
func GetRPCResponse(rpcReq *models.RPCRequest) (respBytes []byte, err error) {
	rpcReq.NodeVersion = Version
	rpcReq.AuthKey = GenAuthKey()
	bytesData, err := json.Marshal(rpcReq)
	utils.CheckError("GetRPCResponse Marshal", err)
	reader := bytes.NewReader(bytesData)
	request, err := http.NewRequest("POST", CFG.ReplicaNode.SyncAddr, reader)
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	client := http.Client{}
	resp, err := client.Do(request)
	utils.CheckError("GetRPCResponse Do", err)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err = ioutil.ReadAll(resp.Body)
	return respBytes, err

}
