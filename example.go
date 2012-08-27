// example.go
//
// A simple HTTP server which presents a reCaptcha input form and evaulates the result,
// using the github.com/dpapathanasiou/go-recaptcha package
//
// Edit the recaptcha_public_key constant before using
package main

import (
    "fmt"
    "log"
    "net/http"
    "recaptcha"
)

const (
    recaptcha_public_key = `...[your public key goes here]...`
    recaptcha_server_form = `https://www.google.com/recaptcha/api/challenge`
    pageTop    = `<!DOCTYPE HTML><html><head>
<style>.error{color:#ff0000;} .ack{color:#0000ff;}</style></head><title>Recaptcha Test</title>
<body><h3>Recaptcha Test</h3>
<p>This is a test form for the go-recaptcha package</p>`
    form       = `<form action="/" method="POST">
    	<script src="%s?k=%s" type="text/javascript"> </script>
    	<input type="submit" name="button" value="Ok">
</form>`
    pageBottom = `</body></html>`
    anError    = `<p class="error">%s</p>`
    anAck      = `<p class="ack">%s</p>`
)

func processRequest(request *http.Request) (result bool) {
    result = false
    challenge, challenge_found := request.Form["recaptcha_challenge_field"]
    recaptcha_resp, resp_found := request.Form["recaptcha_response_field"]
    if challenge_found && resp_found {
    	result = recaptcha.Confirm ("127.0.0.1", challenge[0], recaptcha_resp[0])
    }
    return 
}

func homePage(writer http.ResponseWriter, request *http.Request) {
    err := request.ParseForm() // Must be called before writing response
    fmt.Fprint(writer, pageTop)
    if err != nil {
        fmt.Fprintf(writer, fmt.Sprintf(anError, err))
    } else {
    	_, button_clicked := request.Form["button"]
    	if button_clicked {
    		if processRequest(request) {
    			fmt.Fprint(writer, fmt.Sprintf(anAck, "Recaptcha was correct!"))
    		} else {
    			fmt.Fprintf(writer, fmt.Sprintf(anError, "Recaptcha was incorrect; try again."))
    		}
    	}
    }
    fmt.Fprint(writer, fmt.Sprintf(form, recaptcha_server_form, recaptcha_public_key))
    fmt.Fprint(writer, pageBottom)
}

func main() {
    http.HandleFunc("/", homePage)
    if err := http.ListenAndServe(":9001", nil); err != nil {
        log.Fatal("failed to start server", err)
    }
}