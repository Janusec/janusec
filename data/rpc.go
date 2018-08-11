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

	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func GenAuthKey() string {
	nodeAuth := models.NodeAuth{CurTime: time.Now().Unix()}
	nodeAuthBytes, err := json.Marshal(nodeAuth)
	utils.CheckError("GenAuthKey", err)
	encryptedAuthBytes := EncryptWithKey(nodeAuthBytes, NodeKey)
	return hex.EncodeToString(encryptedAuthBytes)
}

func GetResponse(rpcReq *models.RPCRequest) (respBytes []byte, err error) {
	rpcReq.ObjectID = 0
	rpcReq.NodeID = CFG.NodeID
	rpcReq.NodeVersion = Version
	rpcReq.AuthKey = GenAuthKey()
	bytesData, err := json.Marshal(rpcReq)
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
	respBytes, err = ioutil.ReadAll(resp.Body)
	return respBytes, err

}
