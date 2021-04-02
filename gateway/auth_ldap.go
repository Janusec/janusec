/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-16 15:03:30
 * @Last Modified: U2, 2020-05-16 15:03:30
 */

package gateway

import (
	"janusec/data"
	"net/http"
	"text/template"
)

var (
	ldapLoginTemplate = template.Must(template.New("ldap").Parse(ldapTemplate))
)

// LDAPContext LDAP Context
type LDAPContext struct {
	DisplayName     string
	State           string
	AuthCodeEnabled bool
}

// ShowLDAPLoginUI Show LDAP Login UI
func ShowLDAPLoginUI(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	ldapContext := LDAPContext{
		DisplayName:     data.AuthConfig.LDAP.DisplayName,
		State:           state,
		AuthCodeEnabled: data.AuthConfig.LDAP.AuthenticatorEnabled}
	if err := ldapLoginTemplate.Execute(w, &ldapContext); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const ldapTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"> 
<title>LDAP Authenticaiton</title> 
</head>
<style>
input[type=text],input[type=password] {
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
  width: 40%;
  margin: 20px auto;
}

a {
  font-size: 12px;
  margin-right: 20px;
}

div {
  border-radius: 5px;
  background-color: #f2f2f2;
  padding: 20px;
  width: 40%;
  margin: auto;
}

#zh:target~[data-lang-cn]:after{
    content: attr(data-lang-cn);
}
[data-lang-en]:after, #en:target~[data-lang-cn]:after{
    content: attr(data-lang-en);
}
</style>
<body>

<h1>{{ .DisplayName }}</h1>

<div>
  <form action="/ldap/auth" method="POST">
	<input type="hidden" name="state" value="{{ .State }}">
	<span id="zh"></span>
    <span id="en"></span>
    <label for="username" data-lang-cn="用户名" data-lang-en="Username"></label>
    <input type="text" id="username" name="username" placeholder="Your username">

    <label for="password" data-lang-cn="口令" data-lang-en="Password"></label>
	<input type="password" id="password" name="password" placeholder="Your password">
	{{ if .AuthCodeEnabled }}
	<label for="code" data-lang-cn="Authenticator认证码(首次使用输入000000)" data-lang-en="Authenticator Code (000000 for first use)"></label>
    <input type="text" id="code" name="code" placeholder="Your Authenticator Code">
    {{ end }}
    <input type="submit" value="Login">
  </form>
  <a href="#zh">中文</a>
  <a href="#en">English</a>
</div>

</body>
</html>`
