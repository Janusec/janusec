/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:10
 * @Last Modified: U2, 2018-07-14 16:38:10
 */

package gateway

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	//"net/http/httputil"
	"strings"

	"github.com/Janusec/janusec/backend"
	"github.com/Janusec/janusec/firewall"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

func rewriteResponse(resp *http.Response) (err error) {
	r := resp.Request
	app := backend.GetApplicationByDomain(r.Host)
	locationURL, err := resp.Location()
	if locationURL != nil {
		port := locationURL.Port()
		if (port != "80") && (port != "443") {
			host := locationURL.Hostname()
			//app := backend.GetApplicationByDomain(host)
			if app != nil {
				newLocation := strings.Replace(locationURL.String(), host+":"+port, host, -1)
				userScheme := "http"
				if resp.Request.TLS != nil {
					userScheme = "https"
				}
				newLocation = strings.Replace(newLocation, locationURL.Scheme, userScheme, 1)
				resp.Header.Set("Location", newLocation)
			}
		}
	}

	// Hide X-Powered-By
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		resp.Header.Set("X-Powered-By", "Janusec")
	}

	srcIP := GetClientIP(r, app)
	if app.WAFEnabled {
		if isHit, policy := firewall.IsResponseHitPolicy(resp, app.ID); isHit {
			switch policy.Action {
			case models.Action_Block_100:
				vulnName, _ := firewall.VulnMap.Load(policy.VulnID)
				hitInfo := &models.HitInfo{TypeID: 2, PolicyID: policy.ID, VulnName: vulnName.(string)}
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
				blockContent := GenerateBlockConcent(hitInfo)
				//fmt.Println("rewriteResponse Action_Block_100 blockContent", string(blockContent))
				body := ioutil.NopCloser(bytes.NewReader(blockContent))
				resp.Body = body
				resp.ContentLength = int64(len(blockContent))
				resp.StatusCode = 403
				return nil
			case models.Action_BypassAndLog_200:
				go firewall.LogGroupHitRequest(r, app.ID, srcIP, policy)
			case models.Action_CAPTCHA_300:
				clientID := GenClientID(r, app.ID, srcIP)
				targetURL := r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					targetURL += "?" + r.URL.RawQuery
				}
				hitInfo := &models.HitInfo{TypeID: 2,
					PolicyID: policy.ID, VulnName: "Group Policy Hit",
					Action: policy.Action, ClientID: clientID,
					TargetURL: targetURL, BlockTime: time.Now().Unix()}
				captchaHitInfo.Store(clientID, hitInfo)
				captchaURL := CaptchaEntrance + "?id=" + clientID
				resp.Header.Set("Location", captchaURL)
				resp.ContentLength = 0
				//http.Redirect(w, r, captchaURL, http.StatusTemporaryRedirect)
				return
			default:
				// models.Action_Pass_400 do nothing
			}
		}
	}

	// HSTS
	if (app.HSTSEnabled == true) && (r.TLS != nil) {
		resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Static Cache
	if resp.StatusCode == http.StatusOK && firewall.IsStaticResource(r) {
		staticRoot := fmt.Sprintf("./static/cdncache/%d", app.ID)
		targetFile := staticRoot + r.URL.Path
		cacheFilePath := filepath.Dir(targetFile)
		bodyBuf, _ := ioutil.ReadAll(resp.Body)
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))

		err := os.MkdirAll(cacheFilePath, 0666)
		if err != nil {
			utils.DebugPrintln("Cache Path Error", err)
		}
		contentEncoding := resp.Header.Get("Content-Encoding")
		switch contentEncoding {
		case "gzip":
			reader, err := gzip.NewReader(bytes.NewBuffer(bodyBuf))
			defer reader.Close()
			decompressedBodyBuf, err := ioutil.ReadAll(reader)
			utils.DebugPrintln("Gzip decompress Error", err)
			err = ioutil.WriteFile(targetFile, decompressedBodyBuf, 0666)
		/*
			case "deflate":
				reader := flate.NewReader(bytes.NewBuffer(bodyBuf))
				defer reader.Close()
				decompressedBodyBuf, err := ioutil.ReadAll(reader)
				utils.DebugPrintln("flate decompress Error", err)
				err = ioutil.WriteFile(targetFile, decompressedBodyBuf, 0666)
		*/
		default:
			err = ioutil.WriteFile(targetFile, bodyBuf, 0666)
		}
		if err != nil {
			utils.DebugPrintln("Cache File Error", err)
		}
		lastModified, err := time.Parse(http.TimeFormat, resp.Header.Get("Last-Modified"))
		if err != nil {
			utils.DebugPrintln("Cache File Check Last-Modified", err)
			return nil
		}
		err = os.Chtimes(targetFile, time.Now(), lastModified)
		utils.DebugPrintln("Cache File Check Last-Modified", err)
	}
	//body, err := httputil.DumpResponse(resp, true)
	//fmt.Println("Dump Response:")
	//fmt.Println(string(body))
	return nil
}
