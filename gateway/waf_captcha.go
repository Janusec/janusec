/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:54
 * @Last Modified: U2, 2018-07-14 16:36:54
 */

package gateway

import (
	"html"
	"net/http"
	"sync"
	"text/template"
	"time"

	"janusec/firewall"
	"janusec/models"

	"github.com/dchest/captcha"
)

var (
	captchaHitInfo = sync.Map{} // (clientID string, *HitInfo)
	formTemplate   = template.Must(template.New("captcha").Parse(formTemplateSrc))
)

const (
	// CaptchaEntrance : captcha confirm url
	CaptchaEntrance = "/captcha/confirm"
)

// ShowCaptchaHandlerFunc ...
func ShowCaptchaHandlerFunc(w http.ResponseWriter, r *http.Request) {
	go ClearExpiredCapthchaHitInfo()
	id := html.EscapeString(r.FormValue("id"))
	captchaContext := models.CaptchaContext{CaptchaId: captcha.New(), ClientID: id}
	if err := formTemplate.Execute(w, &captchaContext); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ValidateCaptchaHandlerFunc ...
func ValidateCaptchaHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	clientID := r.FormValue("client_id")
	if !captcha.VerifyString(r.FormValue("captcha_id"), r.FormValue("captcha_solution")) {
		captchaURL := CaptchaEntrance + "?id=" + clientID
		http.Redirect(w, r, captchaURL, http.StatusTemporaryRedirect)
	} else {
		if mapHitInfo, ok := captchaHitInfo.Load(clientID); ok {
			hitInfo := mapHitInfo.(*models.HitInfo)
			captchaHitInfo.Delete(clientID)
			if hitInfo.TypeID == 1 {
				firewall.ClearCCStatByClientID(hitInfo.PolicyID, clientID)
				http.Redirect(w, r, hitInfo.TargetURL, http.StatusFound)
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// ShowCaptchaImage ...
func ShowCaptchaImage() http.Handler {
	return captcha.Server(captcha.StdWidth, captcha.StdHeight)
}

// ClearExpiredCapthchaHitInfo ...
func ClearExpiredCapthchaHitInfo() {
	captchaHitInfo.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		hitInfo := value.(*models.HitInfo)
		curTime := time.Now().Unix()
		if curTime-hitInfo.BlockTime > 600 {
			captchaHitInfo.Delete(clientID)
		}
		return true
	})
}

const formTemplateSrc = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"> 
<title>CAPTCHA</title>
</head>
<style>
input[type=text] {
  width: 100%;
  padding: 12px 20px;
  margin: 8px 0;
  display: inline-block;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-sizing: border-box;
}

input[type=submit] {
  width: 100%;
  background-color: #4CAF50;
  color: white;
  padding: 14px 20px;
  margin: 8px 0;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

input[type=submit]:hover {
  background-color: #45a045;
}

a {
  font-size: 12px;
  margin-right: 20px;
}

div {
  border-radius: 5px;
  background-color: #f2f2f2;
  padding: 20px;
  width: 50%;
  margin: auto;
}

.captcha {
  width: 100%;
}

#zh:target~[data-lang-cn]:after{
    content: attr(data-lang-cn);
}
[data-lang-en]:after, #en:target~[data-lang-cn]:after{
    content: attr(data-lang-en);
}
</style>
<body>

<div>
<form action="/captcha/validate" method="POST">
<span id="zh"></span>
<span id="en"></span>
<p for="note" data-lang-cn="访问频繁，请输入验证码:" data-lang-en="Too many requests, please type the CAPTCHA:"></p>
<p><img id=image class="captcha" src="/captcha/png/{{.CaptchaId}}.png" alt="Captcha image"></p>
<a href="#" onclick="reload()" data-lang-cn="刷新" data-lang-en="Reload"></a>
<input type="hidden" name="captcha_id" value="{{.CaptchaId}}"><br>
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="text" name="captcha_solution">
<input type="submit" value="Submit">
</form>
<a href="#zh">中文</a>
<a href="#en">English</a>
<div>

<script>
if(navigator.language=='zh-CN') window.location.hash = 'zh';

function setSrcQuery(e, q) {
	var src  = e.src;
	var p = src.indexOf('?');
	if (p >= 0) {
		src = src.substr(0, p);
	}
	e.src = src + "?" + q
}

function reload() {
	setSrcQuery(document.getElementById('image'), "reload=" + (new Date()).getTime());
	return false;
}
</script>
</body>
</html>
`
