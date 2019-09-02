package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	auth "github.com/abbot/go-http-auth"
	"github.com/gorilla/mux"
	"github.com/jeremmfr/go-iptables/iptables"
)

func ruleGenerate(r *http.Request) []string {
	vars := mux.Vars(r)
	var specEnd []string

	if r.URL.Query().Get("sports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("state") != "" {
		specEnd = append(specEnd, "-m", "state", "--state", r.URL.Query().Get("state"))
	}
	if r.URL.Query().Get("fragment") != "" {
		specEnd = append(specEnd, "-f")
	}
	if r.URL.Query().Get("icmptype") != "" {
		specEnd = append(specEnd, "--icmp-type", r.URL.Query().Get("icmptype"))
	}
	if vars["iface_in"] != "*" {
		specEnd = append(specEnd, "-i", vars["iface_in"])
	}
	if vars["iface_out"] != "*" {
		specEnd = append(specEnd, "-o", vars["iface_out"])
	}
	srcRange := strings.Contains(vars["source"], "-")
	dstRange := strings.Contains(vars["destination"], "-")
	ruleSpecs := []string{"-p", vars["proto"]}
	if srcRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_32", "", -1))
	} else {
		ruleSpecs = append(ruleSpecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if dstRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_32", "", -1))
	} else {
		ruleSpecs = append(ruleSpecs, "-d", strings.Replace(vars["destination"], "_", "/", -1))
	}
	ruleSpecs = append(ruleSpecs, "-j", vars["action"])
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == logAct {
		ruleSpecs = append(ruleSpecs, "--log-prefix", r.URL.Query().Get("log-prefix"))
	}
	ruleSpecs = append(ruleSpecs, specEnd...)
	return ruleSpecs
}

func checkPosRules(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string

	line := []string{vars["action"], vars["proto"]}
	if r.URL.Query().Get("fragment") != "" {
		line = append(line, "-f")
	} else {
		line = append(line, "--")
	}
	line = append(line, vars["iface_in"], vars["iface_out"])

	srcRange := strings.Contains(vars["source"], "-")
	if srcRange {
		line = append(line, "0.0.0.0/0")
	} else {
		source32 := strings.Contains(vars["source"], "_32")
		if source32 {
			line = append(line, strings.Replace(vars["source"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["source"], "_", "/", -1))
		}
	}

	dstRange := strings.Contains(vars["destination"], "-")
	if dstRange {
		line = append(line, "0.0.0.0/0")
	} else {
		destination32 := strings.Contains(vars["destination"], "_32")
		if destination32 {
			line = append(line, strings.Replace(vars["destination"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
		}
	}
	if srcRange {
		line = append(line, "source", "IP", "range", strings.Replace(vars["source"], "_32", "", -1))
	}
	if dstRange {
		line = append(line, "destination", "IP", "range", strings.Replace(vars["destination"], "_32", "", -1))
	}
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("icmptype") != "" {
		line = append(line, "icmptype", r.URL.Query().Get("icmptype"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	if vars["action"] == "REJECT" {
		line = append(line, "reject-with", "icmp-port-unreachable")
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "filter", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	rules, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(rules); i++ {
		rulesSlice := strings.Fields(rules[i])
		rulesSliceNoVerb := rulesSlice[3:]
		if reflect.DeepEqual(line, rulesSliceNoVerb) {
			linenumber = append(linenumber, rulesSlice[0])
		}
	}
	return linenumber, nil

}

// PUT /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func addRules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := ruleGenerate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	vars := mux.Vars(r)
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		respErr = ipt.Insert("filter", vars["chain"], position, rulespecs...)
	} else {
		respErr = ipt.Append("filter", vars["chain"], rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func delRules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := ruleGenerate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	vars := mux.Vars(r)
	respErr = ipt.Delete("filter", vars["chain"], rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// GET /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func checkRules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := ruleGenerate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		posRules, err := checkPosRules(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posRules) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posRules) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posRules[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		vars := mux.Vars(r)
		respStr, respErr := ipt.Exists("filter", vars["chain"], rulespecs...)
		if respErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, respErr)
			return
		}
		if !respStr {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
}
