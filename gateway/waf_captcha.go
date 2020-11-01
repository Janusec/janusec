/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:54
 * @Last Modified: U2, 2018-07-14 16:36:54
 */

package gateway

import (
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
	id := r.FormValue("id")
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
				http.Redirect(w, r, hitInfo.TargetURL, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, "/", http.StatusMovedPermanently)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
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

const formTemplateSrc = `<!doctype html>
<head>
<title>Captcha Example</title>
</head>
<style>
form {
	display: block;
	width: 30%;
	margin: auto;
}
</style>
<body>
<script>
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
<form action="/captcha/validate" method="POST">
<p>Please type the following numbers:</p>
<p><img id=image src="/captcha/png/{{.CaptchaId}}.png" alt="Captcha image"></p>
<a href="#" onclick="reload()">Reload</a>
<input type="hidden" name="captcha_id" value="{{.CaptchaId}}"><br>
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input name="captcha_solution">
<input type="submit" value="Submit">
</form>
</body>
</html>
`
