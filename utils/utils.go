/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:49
 * @Last Modified: U2, 2018-07-14 16:20:49
 */

package utils

import (
	"fmt"
	"log"
	"strings"
)

const (
	Debug = false
)

func CheckError(msg string, err error) {
	if err != nil {
		log.Println(msg, err)
	}
}

func GetDirAll(path string) string {
	i := strings.LastIndex(path, "/")
	dirAll := path[:i]
	return dirAll
}

func DebugPrintln(a ...interface{}) {
	if Debug {
		fmt.Println(a)
	}
}
