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

// GenerateBlockPage ...
func GenerateBlockPage(w http.ResponseWriter, hitInfo *models.HitInfo) {
	if data.TmplWAF == nil {
		data.TmplWAF, _ = template.New("tmplWAF").Parse(data.NodeSetting.BlockHTML)
	}
	w.WriteHeader(403)
	err := data.TmplWAF.Execute(w, hitInfo)
	if err != nil {
		utils.DebugPrintln("GenerateBlockPage tmpl.Execute error", err)
	}
}

// GenerateBlockContent ...
func GenerateBlockContent(hitInfo *models.HitInfo) []byte {
	if data.TmplWAF == nil {
		data.TmplWAF, _ = template.New("tmplWAF").Parse(data.NodeSetting.BlockHTML)
	}
	buf := &bytes.Buffer{}
	err := data.TmplWAF.Execute(buf, hitInfo)
	if err != nil {
		utils.DebugPrintln("GenerateBlockContent tmpl.Execute error", err)
	}
	return buf.Bytes()
}
