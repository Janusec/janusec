/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:10
 * @Last Modified: U2, 2018-07-14 16:38:10
 */

package gateway

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	//"net/http/httputil"
	"strings"

	"github.com/andybalholm/brotli"

	"janusec/backend"
	"janusec/data"
	"janusec/firewall"
	"janusec/models"
	"janusec/utils"
)

func rewriteResponse(resp *http.Response) (err error) {
	r := resp.Request
	app := backend.GetApplicationByDomain(r.Host)
	locationStr := resp.Header.Get("Location")
	indexHTTP := strings.Index(locationStr, "http")
	if indexHTTP == 0 {
		locationURL, _ := resp.Location()
		host := locationURL.Hostname()
		port := locationURL.Port()
		if host == r.Host {
			var oldHost, newHost string
			if (port == "") || (port == "80") || (port == "443") {
				oldHost = host
			} else {
				oldHost = host + ":" + port
			}
			var userScheme string
			if resp.Request.TLS != nil {
				userScheme = "https"
				if data.CFG.ListenHTTPS == ":443" {
					newHost = host
				} else {
					newHost = host + data.CFG.ListenHTTPS
				}
			} else {
				userScheme = "http"
				if data.CFG.ListenHTTP == ":80" {
					newHost = host
				} else {
					newHost = host + data.CFG.ListenHTTP
				}
			}
			newLocation := strings.Replace(locationURL.String(), oldHost, newHost, -1)
			newLocation = strings.Replace(newLocation, locationURL.Scheme, userScheme, 1)
			resp.Header.Set("Location", newLocation)
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
				resp.StatusCode = 403
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(blockContent))
				resp.ContentLength = int64(len(blockContent))
				resp.Header.Set("Content-Length", fmt.Sprint(len(blockContent)))
				resp.Header.Del("Content-Encoding")
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
				return nil
			default:
				// models.Action_Pass_400 do nothing
			}
		}
	}

	// HSTS
	if (app.HSTSEnabled) && (r.TLS != nil) {
		resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// CSP Content-Security-Policy, 0.9.11+
	if app.CSPEnabled {
		resp.Header.Set("Content-Security-Policy", app.CSP)
	}

	// if client http and backend https, remove "; Secure" and replace https by http
	if (r.TLS == nil) && (app.InternalScheme == "https") {
		cookies := resp.Cookies()
		for _, cookie := range cookies {
			re := regexp.MustCompile(`;\s*Secure`)
			cookieStr := re.ReplaceAllLiteralString(cookie.Raw, "")
			resp.Header.Set("Set-Cookie", cookieStr)
		}
		origin := resp.Header.Get("Access-Control-Allow-Origin")
		if len(origin) > 0 {
			resp.Header.Set("Access-Control-Allow-Origin", strings.Replace(origin, "https", "http", 1))
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if len(csp) > 0 {
			resp.Header.Set("Content-Security-Policy", strings.Replace(origin, "https", "http", -1))
		}
	}

	// Static Cache
	if resp.StatusCode == http.StatusOK && firewall.IsStaticResource(r) {
		if resp.ContentLength < 0 || resp.ContentLength > 1024*1024*10 {
			// Not cache big files which size bigger than 10MB or unknown
			return nil
		}
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
			reader, _ := gzip.NewReader(bytes.NewBuffer(bodyBuf))
			defer reader.Close()
			decompressedBodyBuf, err := ioutil.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("Gzip decompress Error", err)
			}
			_ = ioutil.WriteFile(targetFile, decompressedBodyBuf, 0600)
		case "br":
			reader := brotli.NewReader(bytes.NewBuffer(bodyBuf))
			decompressedBodyBuf, err := ioutil.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("Brotli decompress Error", err)
			}
			_ = ioutil.WriteFile(targetFile, decompressedBodyBuf, 0600)
		case "deflate":
			reader := flate.NewReader(bytes.NewBuffer(bodyBuf))
			defer reader.Close()
			decompressedBodyBuf, err := ioutil.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("deflate decompress Error", err)
			}
			_ = ioutil.WriteFile(targetFile, decompressedBodyBuf, 0600)
		default:
			_ = ioutil.WriteFile(targetFile, bodyBuf, 0600)
		}
		if err != nil {
			utils.DebugPrintln("Cache File Error", targetFile, err)
		}
		lastModified, err := time.Parse(http.TimeFormat, resp.Header.Get("Last-Modified"))
		if err != nil {
			//utils.DebugPrintln("Cache File Parse Last-Modified", targetFile, err)
			return nil
		}
		err = os.Chtimes(targetFile, time.Now(), lastModified)
		if err != nil {
			utils.DebugPrintln("Cache File Chtimes", targetFile, err)
		}
	}

	//body, err := httputil.DumpResponse(resp, true)
	//fmt.Println("Dump Response:")
	//fmt.Println(string(body))
	return nil
}
