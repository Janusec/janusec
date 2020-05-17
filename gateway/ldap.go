/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-16 15:03:30
 * @Last Modified: U2, 2020-05-16 15:03:30
 */

package gateway

import (
	"net/http"
	"text/template"

	"github.com/Janusec/janusec/data"
)

var (
	ldapLoginTemplate = template.Must(template.New("ldap").Parse(ldapTemplate))
)

type LDAPContext struct {
	DisplayName string
	State       string
}

func ShowLDAPLoginUI(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	ldapContext := LDAPContext{
		DisplayName: data.CFG.MasterNode.OAuth.LDAP.DisplayName,
		State:       state}
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
input[type=text],input[type=password],select {
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

div {
  border-radius: 5px;
  background-color: #f2f2f2;
  padding: 20px;
  width: 40%;
  margin: auto;
}
</style>
<body>

<h1>{{ .DisplayName }}</h1>

<div>
  <form action="/ldap/auth" method="POST">
    <input type="hidden" name="state" value="{{ .State }}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" placeholder="Your username..">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" placeholder="Your password..">

    <input type="submit" value="Submit">
  </form>
</div>

</body>
</html>`
