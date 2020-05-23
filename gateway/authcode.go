/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-17 21:45:58
 * @Last Modified: U2, 2020-05-17 21:45:58
 */

package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"text/template"

	"github.com/Janusec/janusec/usermgmt"

	"github.com/Janusec/janusec/utils"

	qrcode "github.com/skip2/go-qrcode"
)

var (
	authCodeUITemplate = template.Must(template.New("authcode").Parse(authcodeTemplate))
)

type AuthCodeContext struct {
	UID       string
	TOTPKey   string
	ImageData string
}

// AuthCodeVerifyFunc Register TOTP in Mobile APP
func AuthCodeVerifyFunc(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("uid")
	totpCode := r.FormValue("code")
	totpCodeInt, _ := strconv.ParseUint(totpCode, 10, 32)
	totpItem, _ := usermgmt.GetTOTPByUID(uid) //data.DAL.GetTOTPItemByUID(uid)
	verifyOK := usermgmt.VerifyCode(totpItem.TOTPKey, uint32(totpCodeInt))
	if verifyOK {
		usermgmt.UpdateTOTPVerified(totpItem.ID)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/oauth/code/register?uid="+uid, http.StatusFound)
}

// ShowAuthCodeRegisterUI used for Authenticator Code register UI
func ShowAuthCodeRegisterUI(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("uid")
	totpItem, _ := usermgmt.GetTOTPByUID(uid)
	// Format: otpauth://totp/uid?secret=XBSWY3DPEHPK3PXP&issuer=JANUSEC
	totpLink := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=JANUSEC", uid, totpItem.TOTPKey)
	var png []byte
	png, err := qrcode.Encode(totpLink, qrcode.Medium, 256)
	if err != nil {
		utils.DebugPrintln("qrcode.Encode", err)
	}
	codeImageText := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	authCodeContext := AuthCodeContext{
		UID:       uid,
		TOTPKey:   totpItem.TOTPKey,
		ImageData: codeImageText,
	}
	if err := authCodeUITemplate.Execute(w, &authCodeContext); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const authcodeTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"> 
<title>Authenticator Registration</title> 
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

h1 {
  margin: 20px auto;
  text-align: center;
}

.qrcode {
  display: block;
  width: 256px;
  height: 256px;
  margin: auto;
}

div {
  border-radius: 5px;
  background-color: #f2f2f2;
  padding: 20px;
  width: 600px;
  margin: auto;
}

a {
  font-size: 12px;
  margin-right: 20px;
}

.secret_key {
  background-color: #D5D5D5;
  text-align: center;
}

#ch:target~[data-lang-ch]:after{
    content: attr(data-lang-ch);
}

[data-lang-en]:after, #en:target~[data-lang-ch]:after{
    content: attr(data-lang-en);
}

</style>
<body>

<div>
<span id="ch"></span>
<span id="en"></span>
<h1 data-lang-ch="Authenticator认证码注册" data-lang-en="Authenticator Registration"></h1>
  <a href="#ch">中文</a>
  <a href="#en">English</a>
  <hr/>
  <p data-lang-ch="请使用如下任何一款手机APP扫描二维码:" data-lang-en="Please scan the qrcode with one of the following Mobile APP: "></p>
  <ul>
  <li>Google Authenticator</li>
  <li>Microsoft Authenticator</li>
  </ul>
  
  <img src="{{ .ImageData }}" class="qrcode" />
  
  <p data-lang-ch="或直接在APP中手工输入如下密钥:" data-lang-en="or input the following Secret Key in your mobile app:"></p>
  <p class="secret_key">{{ .TOTPKey }}</p> 
  <hr/>
  <h2 data-lang-ch="输入APP中6位认证码，完成验证" data-lang-en="Input 6-digits Code to Finish Verification"></h2>
  
  <form action="/oauth/code/verify" method="POST">
    <input type="hidden" name="uid" value="{{ .UID }}">
    <input type="text" id="code" name="code" placeholder="Authenticator Code">
    <input type="submit" value="Verify">
  </form>  
</div>
</body>
</html>`
