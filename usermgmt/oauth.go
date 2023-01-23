/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-22 10:29:15
 * @Last Modified: U2, 2020-03-22 10:29:15
 */

package usermgmt

import (
	"net"
	"net/http"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

func GetOAuthConfig() (*models.OAuthConfig, error) {
	return data.NodeSetting.AuthConfig, nil
}

// RecordAuthLog ...
func RecordAuthLog(r *http.Request, username string, provider string, callback string) {
	// Get REMOTE_ADDR IP Address
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	go utils.AuthLog(clientIP, username, provider, callback)
}
