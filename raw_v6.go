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

func rawGenerateV6(r *http.Request) []string {
	vars := mux.Vars(r)
	var specEnd []string

	if r.URL.Query().Get("sports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("notrack") != "" {
		specEnd = append(specEnd, "--notrack")
	}
	if (r.URL.Query().Get("tcpflag1") != "") && (r.URL.Query().Get("tcpflag2") != "") && (vars["proto"] == tcpStr) {
		tcpflag := []string{"--tcp-flags", r.URL.Query().Get("tcpflag1"), r.URL.Query().Get("tcpflag2")}
		specEnd = append(specEnd, tcpflag...)
	}
	if r.URL.Query().Get("tcpmss") != "" {
		specEnd = append(specEnd, "-m", "tcpmss", "--mss", r.URL.Query().Get("tcpmss"))
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
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_128", "", -1))
	} else {
		ruleSpecs = append(ruleSpecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if dstRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_128", "", -1))
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

func checkPosRawV6(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string

	line := []string{vars["action"], vars["proto"]}
	line = append(line, vars["iface_in"], vars["iface_out"])

	srcRange := strings.Contains(vars["source"], "-")
	if srcRange {
		line = append(line, "::/0")
	} else {
		source128 := strings.Contains(vars["source"], "_128")
		if source128 {
			line = append(line, strings.Replace(vars["source"], "_128", "", -1))
		} else {
			line = append(line, strings.Replace(vars["source"], "_", "/", -1))
		}
	}

	dstRange := strings.Contains(vars["destination"], "-")
	if dstRange {
		line = append(line, "::/0")
	} else {
		destination128 := strings.Contains(vars["destination"], "_128")
		if destination128 {
			line = append(line, strings.Replace(vars["destination"], "_128", "", -1))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
		}
	}
	if srcRange {
		line = append(line, "source", "IP", "range", strings.Replace(vars["source"], "_128", "", -1))
	}
	if dstRange {
		line = append(line, "destination", "IP", "range", strings.Replace(vars["destination"], "_128", "", -1))
	}
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if (r.URL.Query().Get("tcpflag1") != "") && (r.URL.Query().Get("tcpflag2") != "") && (vars["proto"] == tcpStr) {
		line = append(line, tcpStr)
		flags := ""
		if r.URL.Query().Get("tcpflag1") == SYNStr {
			flags = "flags:0x02/"
		}
		if (r.URL.Query().Get("tcpflag1") == defaultFlagsMask) || (r.URL.Query().Get("tcpflag1") == defaultFlagsMask2) {
			flags = "flags:0x17/"
		}
		if r.URL.Query().Get("tcpflag2") == SYNStr {
			flags = strings.Join([]string{flags, "0x02"}, "")
		}
		line = append(line, flags)
	}
	if r.URL.Query().Get("tcpmss") != "" {
		line = append(line, "tcpmss", "match", r.URL.Query().Get("tcpmss"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "raw", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	raws, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(raws); i++ {
		rawsSlice := strings.Fields(raws[i])
		rawsSliceNoVerb := rawsSlice[3:]
		if reflect.DeepEqual(line, rawsSliceNoVerb) {
			linenumber = append(linenumber, rawsSlice[0])
		}
	}
	return linenumber, nil
}

// PUT /raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func addRawV6(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerateV6(r)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		respErr = ipt.Insert("raw", vars["chain"], position, rulespecs...)
	} else {
		respErr = ipt.Append("raw", vars["chain"], rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DELTE /raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func delRawV6(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerateV6(r)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("raw", vars["chain"], rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// GET /raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func checkRawV6(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerateV6(r)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		if r.URL.Query().Get("tcpflag1") != "" {
			if (r.URL.Query().Get("tcpflag1") != defaultFlagsMask) && (r.URL.Query().Get("tcpflag1") != SYNStr) && (r.URL.Query().Get("tcpflag1") != defaultFlagsMask2) {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "tcpflag", r.URL.Query().Get("tcpflag1"), "and position not compatible")
				return
			}
		}
		if r.URL.Query().Get("tcpflag2") != "" {
			if r.URL.Query().Get("tcpflag2") != SYNStr {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "tcpflag", r.URL.Query().Get("tcpflag2"), "and position not compatible")
				return
			}
		}
		posRaw, err := checkPosRawV6(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posRaw) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posRaw) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posRaw[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		vars := mux.Vars(r)
		respStr, respErr := ipt.Exists("raw", vars["chain"], rulespecs...)
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
