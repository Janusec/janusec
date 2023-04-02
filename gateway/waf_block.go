/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:30
 * @Last Modified: U2, 2018-07-14 16:38:30
 */

package gateway

import (
	"bytes"
	"html/template"
	"net/http"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var tmplBlockReq, tmplBlockResp *template.Template

// GenerateBlockPage ...
func GenerateBlockPage(w http.ResponseWriter, hitInfo *models.HitInfo) {
	if tmplBlockReq == nil {
		tmplBlockReq, _ = template.New("blockReq").Parse(data.NodeSetting.BlockHTML)
	}
	w.WriteHeader(403)
	err := tmplBlockReq.Execute(w, hitInfo)
	if err != nil {
		utils.DebugPrintln("GenerateBlockPage tmpl.Execute error", err)
	}
}

// GenerateBlockConcent ...
func GenerateBlockConcent(hitInfo *models.HitInfo) []byte {
	if tmplBlockResp == nil {
		tmplBlockResp, _ = template.New("blockResp").Parse(data.NodeSetting.BlockHTML)
	}
	buf := &bytes.Buffer{}
	err := tmplBlockResp.Execute(buf, hitInfo)
	if err != nil {
		utils.DebugPrintln("GenerateBlockConcent tmpl.Execute error", err)
	}
	return buf.Bytes()
}
