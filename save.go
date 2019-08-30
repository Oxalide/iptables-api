package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	auth "github.com/abbot/go-http-auth"
)

// GET /save/
func saveRules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	err := os.MkdirAll("/etc/iptables/", 0755)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	stdout, err := exec.Command("iptables-save").Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = ioutil.WriteFile("/etc/iptables/rules.v4", stdout, 0644)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = os.MkdirAll(*savePath, 0755)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	currentTime := time.Now().Local()
	dstFile := []string{*savePath, "rules.v4.", currentTime.Format("2006-01-02"), ".", currentTime.Format("15-04-05")}
	cmd := exec.Command("cp", "/etc/iptables/rules.v4", strings.Join(dstFile, ""))
	err = cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, strings.Join(dstFile, ""))
}

// GET /restore/{file}
func restoreRules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	err := exec.Command("iptables-restore", r.URL.Query().Get("file")).Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
