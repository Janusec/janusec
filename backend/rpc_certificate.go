/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:23:18
 * @Last Modified: U2, 2018-07-14 16:23:18
 */

package backend

import (
	"crypto/tls"
	"encoding/json"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

// RPCSelectCertificates ...
func RPCSelectCertificates() []*models.CertItem {
	certs := []*models.CertItem{}
	rpcRequest := &models.RPCRequest{
		Action: "get_certs", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCSelectCertificates GetResponse", err)
		return certs
	}
	rpcCertItems := &models.RPCCertItems{}
	if err = json.Unmarshal(resp, rpcCertItems); err != nil {
		utils.DebugPrintln("RPCSelectCertificates Unmarshal", err)
		return certs
	}
	certItems := rpcCertItems.Object
	for _, certItem := range certItems {
		certItem.TlsCert, err = tls.X509KeyPair([]byte(certItem.CertContent), []byte(certItem.PrivKeyContent))
		if err != nil {
			utils.DebugPrintln("RPCSelectCertificates X509KeyPair", err)
		}
		certs = append(certs, certItem)
	}
	return certs
}
