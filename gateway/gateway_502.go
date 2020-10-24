/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-18 10:58:30
 * @Last Modified: U2, 2020-10-18 10:58:30
 */

package gateway

import (
	"html/template"
	"net/http"

	"janusec/models"
	"janusec/utils"
)

var tmpl502 *template.Template

// GenerateInternalErrorResponse ...
func GenerateInternalErrorResponse(w http.ResponseWriter, errInfo *models.InternalErrorInfo) {
	if tmpl502 == nil {
		tmpl502, _ = template.New("InternalError").Parse(internalErrorHTML)
	}

	err := tmpl502.Execute(w, errInfo)
	if err != nil {
		utils.DebugPrintln("GenerateInternalErrorResponse tmpl.Execute error", err)
	}
}

const internalErrorHTML = `<!DOCTYPE html>
 <html>
 <head>
 <title>Internal Error</title>
 </head>
 <style>
 body {
	 font-family: Arial, Helvetica, sans-serif;
	 text-align: center;
 }
  
 .block_div {
	 padding: 10px;
	 width: 70%;    
	 margin: auto;
 }
 
 </style>
 <body>
 <div class="block_div">
 <h1>Internal Server Offline</h1>
 <hr>
 {{ .Description }}. Detected by Janusec Application Gateway
 </div>
 </body>
 </html>
 `
