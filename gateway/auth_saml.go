/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-31 20:01:54
 * @Last Modified: U2, 2020-05-31 20:01:54
 */

package gateway

import (
	"fmt"
	"net/http"
)

// SAMLLogin SAML2.0 Login
func SAMLLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SAMLLogin ToDo")
	/*
		cert, err := backend.GetCertificateByDomain(r.URL.Host)
		samlSP, _ := samlsp.New(samlsp.Options{
			URL:            *rootURL,
			Key:            cert.PrivateKey.(*rsa.PrivateKey),
			Certificate:    cert.Leaf,
			IDPMetadataURL: idpMetadataURL,
		})
		samlSP.HandleStartAuthFlow(w, r)
	*/
}
