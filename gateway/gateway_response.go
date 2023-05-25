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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	//"net/http/httputil"
	"strings"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/html"

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
				blockContent := GenerateBlockContent(hitInfo)
				resp.StatusCode = 403
				resp.Body = io.NopCloser(bytes.NewBuffer(blockContent))
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
	if app.HSTSEnabled {
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
		bodyBuf, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
		err := os.MkdirAll(cacheFilePath, 0666)
		if err != nil {
			utils.DebugPrintln("Cache Path Error", err)
		}
		contentEncoding := resp.Header.Get("Content-Encoding")
		switch contentEncoding {
		case "gzip":
			reader, _ := gzip.NewReader(bytes.NewBuffer(bodyBuf))
			defer reader.Close()
			decompressedBodyBuf, err := io.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("Gzip decompress Error", err)
			}
			_ = os.WriteFile(targetFile, decompressedBodyBuf, 0600)
		case "br":
			reader := brotli.NewReader(bytes.NewBuffer(bodyBuf))
			decompressedBodyBuf, err := io.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("Brotli decompress Error", err)
			}
			_ = os.WriteFile(targetFile, decompressedBodyBuf, 0600)
		case "deflate":
			reader := flate.NewReader(bytes.NewBuffer(bodyBuf))
			defer reader.Close()
			decompressedBodyBuf, err := io.ReadAll(reader)
			if err != nil {
				utils.DebugPrintln("deflate decompress Error", err)
			}
			_ = os.WriteFile(targetFile, decompressedBodyBuf, 0600)
		default:
			_ = os.WriteFile(targetFile, bodyBuf, 0600)
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

	// Test Add DOM to body
	contentType := resp.Header.Get("Content-Type")
	if strings.Index(contentType, "text/html") == 0 {
		doc, err := html.Parse(resp.Body)
		if err != nil {
			fmt.Println("html.Parse error", err)
		}
		body := getNodeByData(doc, "body")
		if body != nil {
			cookieNode, err := html.Parse(strings.NewReader(cookieDiv))
			if err != nil {
				fmt.Println("html.Parse error", err)
			}
			body.AppendChild(cookieNode)

			head := getNodeByData(doc, "head")
			if head != nil {
				cookieStyle, err := html.Parse(strings.NewReader(cookieStyle))
				if err != nil {
					fmt.Println("html.Parse error", err)
				}
				head.AppendChild(cookieStyle)
			}
		}
		// write back to resp.Body
		var bytesBuffer bytes.Buffer
		err = html.Render(&bytesBuffer, doc)
		if err != nil {
			fmt.Println("html.Render error", err)
		}
		newBody := bytesBuffer.Bytes()
		resp.Body = io.NopCloser(bytes.NewBuffer(newBody))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(newBody)), 10))
	}

	/*
		body, err := httputil.DumpResponse(resp, true)
		if err != nil {
			fmt.Println("httputil.DumpResponse error", err)
		}
		fmt.Println("Dump Response:")
		fmt.Println(string(body))
	*/
	return nil
}

func getNodeByData(node *html.Node, data string) *html.Node {
	if node.Type == html.ElementNode && node.Data == data {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		childNode := getNodeByData(child, data)
		if childNode != nil {
			return childNode
		}
	}
	return nil
}

const cookieDiv = `<div #JanusecCookie class="janusec-cookie-preference">
<div class="cookie-container">
	<h3>Cookie Preference</h3>
	<p>We use necessary cookies to make our site work. We'd also like to set analytics cookies that help us make
		improvements by measuring how you use the site. These will be set only if you accept.
		For more detailed information about the cookies we use, see our cookies policy.</p>
	<div>
		<button class="btn-cookie-preference">Reject all cookies</button>
		<span>&nbsp;&nbsp;&nbsp;&nbsp;</span>
		<button class="btn-cookie-preference">Accept all cookies</button>
	</div>
	<hr>
	
	<div class="tab">
		<button class="tablinks" onclick="openCity(event, 'Necessary')" id="defaultOpen">Necessary</button>
		<button class="tablinks" onclick="openCity(event, 'Analytics')">Analytics</button>
		<button class="tablinks" onclick="openCity(event, 'Marketing')">Marketing</button>
	</div>
	  
	<div id="Necessary" class="tabcontent">
		<h3>Necessary</h3>
		<p>Necessary cookies enable core functionality such as security, network management, and accessibility. You
		may disable these by changing your browser settings, but this may affect how the website functions.
	</p>
	</div>
	  
	<div id="Analytics" class="tabcontent">
		<h3>Analytics</h3>
		<p>These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site. They help us to know which pages are the most and least popular and see how visitors move around the site. All information these cookies collect is aggregated and therefore anonymous. However, the third parties providing these services, they will process your personal data in order to provide the aggregated data.</p> 
	</div>
	  
	<div id="Marketing" class="tabcontent">
		<h3>Marketing</h3>
		<p>These cookies are set by our advertising partners. They are used to build a profile of your interests and show relevant ads on other websites, and to also allow you to 'Like' and 'Share' our content on social media. They do not store directly personal information, but are based on uniquely identifying your browser and internet device. Additionally, the third parties setting these cookies may link your personal data with your browsing behaviour if you are logged into their services at the time.</p>
	</div>
</div>
<div class="cookie-window-footer">
	<small>Powered by JANUSEC</small>
</div>
<script>
function openCity(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen").click();
</script>
</div>`

const cookieStyle = `<style>
.janusec-cookie-preference {
	position: absolute;
	top: 200px;
	left: 50%;
	padding: 0;
	margin-left: -300px;
	z-index: 9999;
	width: 600px;
	background-color: #f9f9f9;
	border: 1px solid #e0e0e0;
	opacity: 1;
}

.cookie-container {
	margin: 0 10px;
}

.btn-cookie-preference {
	padding: 10px;
	color: #ffffff;
	border: solid 1px #303030;
	background-color: #6699DD;
}

.cookie-window-footer {
	background-color: #f0f0f0;
	text-align: right;
	padding: 5px;
}

* {box-sizing: border-box}
body {font-family: "Lato", sans-serif;}

/* Style the tab */
.tab {
  float: left;
  border: 1px solid #ccc;
  background-color: #f1f1f1;
  width: 30%;
  height: 300px;
}

/* Style the buttons inside the tab */
.tab button {
  display: block;
  background-color: inherit;
  color: black;
  padding: 22px 16px;
  width: 100%;
  border: none;
  outline: none;
  text-align: left;
  cursor: pointer;
  transition: 0.3s;
  font-size: 17px;
}

/* Change background color of buttons on hover */
.tab button:hover {
  background-color: #ddd;
}

/* Create an active/current "tab button" class */
.tab button.active {
  background-color: #ccc;
}

/* Style the tab content */
.tabcontent {
  float: left;
  padding: 0px 12px;
  border: 1px solid #ccc;
  width: 70%;
  border-left: none;
  height: 300px;
}
</style>`
