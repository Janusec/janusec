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
	"io"
	"net/http"
	"time"

	"janusec/models"
	"janusec/utils"
)

// GenAuthKey for authentication between replica nodes and primary node
func GenAuthKey() string {
	nodeAuth := models.NodeAuth{CurTime: time.Now().Unix()}
	nodeAuthBytes, err := json.Marshal(nodeAuth)
	if err != nil {
		utils.DebugPrintln("GenAuthKey", err)
	}
	encryptedAuthBytes := EncryptWithKey(nodeAuthBytes, NodesKey)
	return hex.EncodeToString(encryptedAuthBytes)
}

// GetRPCResponse ...
func GetRPCResponse(rpcReq *models.RPCRequest) (respBytes []byte, err error) {
	rpcReq.NodeVersion = Version
	rpcReq.AuthKey = GenAuthKey()
	bytesData, err := json.Marshal(rpcReq)
	if err != nil {
		utils.DebugPrintln("GetRPCResponse Marshal", err)
	}
	reader := bytes.NewReader(bytesData)
	request, err := http.NewRequest("POST", CFG.ReplicaNode.SyncAddr, reader)
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		utils.DebugPrintln("GetRPCResponse Do", err)
	}
	if err != nil {
		utils.DebugPrintln("GetRPCResponse Do", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err = io.ReadAll(resp.Body)
	return respBytes, err

}
