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

func dnatGenerateV6(r *http.Request) []string {
	vars := mux.Vars(r)
	rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface"]})
	if r.URL.Query().Get("except") == trueStr {
		rulespecs = append(rulespecs, "!")
	}
	srcRange := strings.Contains(vars["source"], "-")
	dstRange := strings.Contains(vars["destination"], "-")
	if srcRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_128", "", -1))
	} else {
		rulespecs = append(rulespecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if dstRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_128", "", -1))
	} else {
		rulespecs = append(rulespecs, "-d", strings.Replace(vars["destination"], "_", "/", -1))
	}
	rulespecs = append(rulespecs, "-j", "DNAT", "--to-destination", vars["nat_final"])
	if r.URL.Query().Get("dport") != "" {
		rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if r.URL.Query().Get("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}
	return rulespecs
}

func snatGenerateV6(r *http.Request) []string {
	vars := mux.Vars(r)
	rulespecs := append([]string{"-p", vars["proto"], "-o", vars["iface"]})
	srcRange := strings.Contains(vars["source"], "-")
	dstRange := strings.Contains(vars["destination"], "-")
	if srcRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_128", "", -1))
	} else {
		rulespecs = append(rulespecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if r.URL.Query().Get("except") == trueStr {
		rulespecs = append(rulespecs, "!")
	}
	if dstRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_128", "", -1))
	} else {
		rulespecs = append(rulespecs, "-d", strings.Replace(vars["destination"], "_", "/", -1))
	}
	rulespecs = append(rulespecs, "-j", "SNAT", "--to-source", vars["nat_final"])
	if r.URL.Query().Get("dport") != "" {
		rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if r.URL.Query().Get("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}
	return rulespecs
}

func checkPosNatV6(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string
	var line []string

	if vars["action"] == dnatAct {
		line = append(line, "DNAT", vars["proto"], vars["iface"], "*")
	}
	if vars["action"] == snatAct {
		line = append(line, "SNAT", vars["proto"], "*", vars["iface"])
	}
	source128 := strings.Contains(vars["source"], "_128")
	destination128 := strings.Contains(vars["destination"], "_128")

	if source128 {
		if (vars["action"] == dnatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.Replace(vars["source"], "_128", "", -1)}, ""))
		} else {
			line = append(line, strings.Replace(vars["source"], "_128", "", -1))
		}
	} else {
		if (vars["action"] == dnatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.Replace(vars["source"], "_", "/", -1)}, ""))
		} else {
			line = append(line, strings.Replace(vars["source"], "_", "/", -1))
		}
	}
	if destination128 {
		if (vars["action"] == snatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.Replace(vars["destination"], "_128", "", -1)}, ""))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_128", "", -1))
		}
	} else {
		if (vars["action"] == snatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.Replace(vars["destination"], "_", "/", -1)}, ""))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
		}
	}
	if r.URL.Query().Get("dport") != "" {
		line = append(line, "tcp", strings.Join([]string{"dpt:", r.URL.Query().Get("dport")}, ""))
	}
	if r.URL.Query().Get("nth_every") != "" {
		if r.URL.Query().Get("nth_packet") == "0" {
			line = append(line, "statistic", "mode", "nth", "every", r.URL.Query().Get("nth_every"))
		} else {
			line = append(line, "statistic", "mode", "nth", "every", r.URL.Query().Get("nth_every"), "packet", r.URL.Query().Get("nth_packet"))
		}
	}
	line = append(line, strings.Join([]string{"to:", vars["nat_final"]}, ""))

	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "nat", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	nats, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(nats); i++ {
		natsSlice := strings.Fields(nats[i])
		natsSliceNoVerb := natsSlice[3:]
		if reflect.DeepEqual(line, natsSliceNoVerb) {
			linenumber = append(linenumber, natsSlice[0])
		}
	}
	return linenumber, nil
}

// PUT /nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func addNatV6(w http.ResponseWriter, r *http.Request) {
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
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch vars["action"] {
	case dnatAct:
		rulespecs = dnatGenerateV6(r)
	case snatAct:
		rulespecs = snatGenerateV6(r)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		respErr = ipt.Insert("nat", vars["chain"], position, rulespecs...)
	} else {
		respErr = ipt.Append("nat", vars["chain"], rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DELETE /nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func delNatV6(w http.ResponseWriter, r *http.Request) {
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
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch vars["action"] {
	case dnatAct:
		rulespecs = dnatGenerateV6(r)
	case snatAct:
		rulespecs = snatGenerateV6(r)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("nat", vars["chain"], rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// GET /nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func checkNatV6(w http.ResponseWriter, r *http.Request) {
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
	if r.URL.Query().Get("position") != "" {
		posNat, err := checkPosNatV6(r)

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posNat) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posNat) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posNat[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch vars["action"] {
	case dnatAct:
		rulespecs = dnatGenerateV6(r)
	case snatAct:
		rulespecs = snatGenerateV6(r)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respStr, respErr := ipt.Exists("nat", vars["chain"], rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	if !respStr {
		w.WriteHeader(http.StatusNotFound)
	}
}
