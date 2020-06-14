/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:26
 * @Last Modified: U2, 2018-07-14 16:36:26
 */

package gateway

import (
	"net/http"
)

// AdminHandlerFunc is for /janusec-admin
func AdminHandlerFunc(w http.ResponseWriter, r *http.Request) {
	staticHandler := http.FileServer(http.Dir("static"))
	staticHandler.ServeHTTP(w, r)
}
