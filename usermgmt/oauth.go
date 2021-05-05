/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-22 10:29:15
 * @Last Modified: U2, 2020-03-22 10:29:15
 */

package usermgmt

import (
	"io/ioutil"
	"net"
	"net/http"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

func GetOAuthConfig() (*models.OAuthConfig, error) {
	return data.NodeSetting.AuthConfig, nil
}

func GetResponse(request *http.Request) (respBytes []byte, err error) {
	request.Header.Set("Accept", "application/json")
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		utils.DebugPrintln("GetResponse Do", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err = ioutil.ReadAll(resp.Body)
	return respBytes, err
}

// RecordAuthLog ...
func RecordAuthLog(r *http.Request, username string, provider string, callback string) {
	// Get REMOTE_ADDR IP Address
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	go utils.AuthLog(clientIP, username, provider, callback)
}
