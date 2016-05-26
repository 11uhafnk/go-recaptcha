// Package recaptcha handles reCaptcha (http://www.google.com/recaptcha) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers reCaptcha form inputs and requires them to be evaluated for correctness
//
// Edit the recaptcha_private_key constant before building and using
package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const recaptcha_server_name = "https://www.google.com/recaptcha/api/siteverify"

var recaptcha_private_key string

// check uses the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func check(remoteip, response string) (body []byte) {
	log.Printf(`curl -data "secret=%s&remoteip=%s&response=%s %s"`, recaptcha_private_key, remoteip, response, recaptcha_server_name)
	resp, err := http.PostForm(recaptcha_server_name,
		url.Values{"secret": {recaptcha_private_key}, "remoteip": {remoteip}, "response": {response}})
	if err != nil {
		log.Println("Post error: %s", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Read error: could not read body: %s", err)
	}
	return
}

// Confirm is the public interface function.
// It calls check, which the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func Confirm(rr *http.Request) (result bool) {

	result = false
	gRecaptchaResponse, respFound := rr.Form["g-recaptcha-response"]
	log.Printf("gRecaptchaResponse[0]:%s", gRecaptchaResponse[0])
	log.Printf("gRecaptchaResponse:%s", gRecaptchaResponse)
	remoteip := rr.RemoteAddr[:strings.Index(rr.RemoteAddr, ":")]

	type _answer struct {
		Success     bool // признак успешного прохождения
		ChallengeTs time.Time
		HostName    string
		ErrorCodes  []string
	}
	answer := _answer{}

	log.Printf("%v && %v", respFound, remoteip)

	if respFound && remoteip != "" {
		body := check(remoteip, gRecaptchaResponse[0])
		log.Printf("response:%s", string(body))
		if err := json.Unmarshal(body, &answer); err != nil {
			log.Print(err.Error())

			return false
		}

		// if len(answer.ErrorCodes) > 0 {
		log.Printf("%+v", answer)
		// }

		return answer.Success
	}

	return false
}

// Init allows the webserver or code evaluating the reCaptcha form input to set the
// reCaptcha private key (string) value, which will be different for every domain.
func Init(key string) {
	recaptcha_private_key = key
}
