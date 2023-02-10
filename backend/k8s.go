/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-01-23 10:21:54
 */

package backend

import (
	"encoding/json"
	"hash/fnv"
	"janusec/models"
	"janusec/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

func UpdatePods(dest *models.Destination, nowTimeStamp int64) {
	dest.IsUpdating = true
	dest.Mutex.Lock() // write lock
	defer dest.Mutex.Unlock()
	request, _ := http.NewRequest("GET", dest.PodsAPI, nil)
	request.Header.Set("Content-Type", "application/json")
	resp, err := utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("Check K8S API GetResponse", err)
		dest.CheckTime = nowTimeStamp
		dest.Online = false
	}
	pods := models.PODS{}
	err = json.Unmarshal(resp, &pods)
	if err != nil {
		utils.DebugPrintln("Unmarshal K8S API", err)
	}
	dest.Pods = ""
	for _, podItem := range pods.Items {
		if podItem.Status.Phase == "Running" {
			if len(dest.Pods) > 0 {
				dest.Pods += "|"
			}
			dest.Pods += podItem.Status.PodIP + ":" + dest.PodPort
		}
	}
	dest.IsUpdating = false
}

func SelectPodFromDestination(dest *models.Destination, srcIP string, r *http.Request) string {
	nowTimeStamp := time.Now().Unix()
	var isEmptyPods bool
	if len(dest.Pods) == 0 {
		isEmptyPods = true
	} else {
		isEmptyPods = false
	}
	wg := new(sync.WaitGroup)
	if !dest.IsUpdating && (isEmptyPods || (nowTimeStamp-dest.CheckTime) > 60) {
		if isEmptyPods {
			wg.Add(1)
		}
		// check k8s api if exceed 60 seconds
		go func(dest *models.Destination, nowTimeStamp int64, wg *sync.WaitGroup) {
			UpdatePods(dest, nowTimeStamp)
			if isEmptyPods {
				wg.Done()
			}
		}(dest, nowTimeStamp, wg)
	}
	if isEmptyPods {
		wg.Wait()
	}
	dest.Mutex.RLock()
	// select target pod from dest.Pods directly
	dests := strings.Split(dest.Pods, "|")
	// According to Hash(IP+UA)
	h := fnv.New32a()
	_, err := h.Write([]byte(srcIP + r.UserAgent()))
	if err != nil {
		utils.DebugPrintln("SelectPodFromDestination h.Write", err)
	}
	hashUInt32 := h.Sum32()
	destIndex := hashUInt32 % uint32(len(dests))
	dest.Mutex.RUnlock()
	return dests[destIndex]
}

// SelectPodFromVIPTarget get pod for Layer-4 forward
func SelectPodFromVIPTarget(dest *models.VipTarget, srcIP string) string {
	nowTimeStamp := time.Now().Unix()
	if len(dest.Pods) == 0 || (nowTimeStamp-dest.CheckTime) > 60 {
		// check k8s api
		request, _ := http.NewRequest("GET", dest.PodsAPI, nil)
		request.Header.Set("Content-Type", "application/json")
		resp, err := utils.GetResponse(request)
		if err != nil {
			utils.DebugPrintln("Check K8S API GetResponse", err)
			dest.CheckTime = nowTimeStamp
			dest.Online = false
		}
		pods := models.PODS{}
		err = json.Unmarshal(resp, &pods)
		if err != nil {
			utils.DebugPrintln("Unmarshal K8S API", err)
		}
		dest.Pods = ""
		for _, podItem := range pods.Items {
			if podItem.Status.Phase == "Running" {
				if len(dest.Pods) > 0 {
					dest.Pods += "|"
				}
				dest.Pods += podItem.Status.PodIP + ":" + dest.PodPort
			}
		}
	}
	// select target pod from dest.Pods directly
	dests := strings.Split(dest.Pods, "|")
	// According to Hash(IP+UA)
	h := fnv.New32a()
	_, err := h.Write([]byte(srcIP))
	if err != nil {
		utils.DebugPrintln("SelectPodFromVIPTarget h.Write", err)
	}
	hashUInt32 := h.Sum32()
	destIndex := hashUInt32 % uint32(len(dests))
	return dests[destIndex]
}
