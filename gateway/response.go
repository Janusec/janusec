/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:10
 * @Last Modified: U2, 2018-07-14 16:38:10
 */

package gateway

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"
	//"net/http/httputil"
	"strings"
	//"io/ioutil"
	"github.com/Janusec/janusec/backend"
	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func rewriteResponse(resp *http.Response) (err error) {
	utils.DebugPrintln("rewriteResponse")
	r := resp.Request
	app := backend.GetApplicationByDomain(r.Host)
	locationUrl, err := resp.Location()
	if locationUrl != nil {
		port := locationUrl.Port()
		if (port != "80") && (port != "443") {
			host := locationUrl.Hostname()
			//app := backend.GetApplicationByDomain(host)
			if app != nil {
				newLocation := strings.Replace(locationUrl.String(), host+":"+port, host, -1)
				userScheme := "http"
				if resp.Request.TLS != nil {
					userScheme = "https"
				}
				newLocation = strings.Replace(newLocation, locationUrl.Scheme, userScheme, 1)
				//fmt.Println("newLocation", newLocation)
				resp.Header.Set("Location", newLocation)
			}
		}
	}

	// Hide X-Powered-By
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		resp.Header.Set("X-Powered-By", "Janusec")
	}

	if app.WAFEnabled {
		srcIP := GetClientIP(r, app)
		if isHit, policy := firewall.IsResponseHitPolicy(resp, app.ID); isHit {
			switch policy.Action {
			case models.Action_Block_100:
				vulnName, _ := firewall.VulnMap.Load(policy.VulnID)
				hitInfo := &models.HitInfo{TypeID: 2, PolicyID: policy.ID, VulnName: vulnName.(string)}
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
				block_content := GenerateBlockConcent(hitInfo)
				//fmt.Println("rewriteResponse Action_Block_100 block_content", string(block_content))
				body := ioutil.NopCloser(bytes.NewReader(block_content))
				resp.Body = body
				resp.ContentLength = int64(len(block_content))
				resp.StatusCode = 403
				return nil
			case models.Action_BypassAndLog_200:
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
			case models.Action_CAPTCHA_300:
				clientID := GenClientID(r, app.ID, srcIP)
				targetUrl := r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					targetUrl += "?" + r.URL.RawQuery
				}
				hitInfo := &models.HitInfo{TypeID: 2,
					PolicyID: policy.ID, VulnName: "Group Policy Hit",
					Action: policy.Action, ClientID: clientID,
					TargetURL: targetUrl, BlockTime: time.Now().Unix()}
				captchaHitInfo.Store(clientID, hitInfo)
				captchaUrl := CaptchaEntrance + "?id=" + clientID
				resp.Header.Set("Location", captchaUrl)
				resp.ContentLength = 0
				//http.Redirect(w, r, captchaUrl, http.StatusTemporaryRedirect)
				return
			default:
				// models.Action_Pass_400 do nothing
			}
		}
	}

	// HSTS
	if (app.HSTSEnabled == true) && (resp.Request.TLS != nil) {
		resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	//body, err := httputil.DumpResponse(resp, true)
	//fmt.Println("Dump Response:")
	//fmt.Println(string(body))
	return nil
}
