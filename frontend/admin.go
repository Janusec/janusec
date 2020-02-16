/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:26
 * @Last Modified: U2, 2018-07-14 16:36:26
 */

package frontend

import (
	"net/http"
)

func AdminHandlerFunc(w http.ResponseWriter, r *http.Request) {
	/*
		filename := "." + r.URL.Path
		fmt.Println("adminHandlerFunc:", filename, r.URL.Path)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			http.Redirect(w, r, "/janusec-admin/", http.StatusMovedPermanently)
			return
		}
	*/
	staticHandler := http.FileServer(http.Dir("static"))
	staticHandler.ServeHTTP(w, r)
}
