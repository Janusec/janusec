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
	"fmt"
	"io"
	"net/http"
	"time"

	"janusec/models"
	"janusec/utils"
)

// GenAuthKey
// Using NodesKey for authentication between replica nodes and primary node
// Using DataDiscoveryKey for data dicovery report
func GenAuthKey(key []byte) string {
	authTime := models.AuthTime{CurTime: time.Now().Unix()}
	nodeAuthBytes, err := json.Marshal(authTime)
	if err != nil {
		utils.DebugPrintln("GenAuthKey", err)
	}
	fmt.Println("GenAuthKey", authTime, string(nodeAuthBytes), key)
	encryptedAuthBytes := EncryptWithKey(nodeAuthBytes, key)
	return hex.EncodeToString(encryptedAuthBytes)
}

// GetRPCResponse ...
func GetRPCResponse(rpcReq *models.RPCRequest) (respBytes []byte, err error) {
	rpcReq.NodeVersion = Version
	rpcReq.AuthKey = GenAuthKey(NodesKey)
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
