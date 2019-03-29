// Copyright 2016 Jeremy Muriel
//
// This file is part of iptables-api.
// 
// iptables-api is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//  
// Foobar is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with iptables-api.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"strings"
	"log"
	"net/http"
	"os"
	"os/exec"
	"io/ioutil"
	"time"
	"flag"
	"reflect"
	"strconv"

	auth "github.com/abbot/go-http-auth"
	"github.com/oxalide/go-iptables/iptables"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

var (
	resp_err error
	htpasswdfile *string
	save_path *string
)

func main() {
	listen_ip := flag.String("ip", "127.0.0.1", "listen on IP")
	listen_port := flag.String("port", "8080", "listen on port")
	https := flag.Bool("https", false, "https = true or false")
	cert := flag.String("cert", "", "file of certificat for https")
	key := flag.String("key", "", "file of key for https")
	accessLogFile := flag.String("log", "/var/log/iptables-api.access.log", "file for access log")
	htpasswdfile = flag.String("htpasswd", "", "htpasswd file for login:password")
	save_path = flag.String("savepath", "/var/backups/iptables-api/", "path for backups file on /save")

	flag.Parse()

	// accesslog file open
	accessLog, err := os.OpenFile(*accessLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open access log: %s", err)
	}


	// create router
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", add_rules).Methods("PUT")
	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", del_rules).Methods("DELETE")
	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", check_rules).Methods("GET")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", add_raw).Methods("PUT")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", del_raw).Methods("DELETE")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", check_raw).Methods("GET")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", add_nat).Methods("PUT")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", del_nat).Methods("DELETE")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", check_nat).Methods("GET")
	router.HandleFunc("/chain/{table}/{name}/", add_chain).Methods("PUT")
	router.HandleFunc("/chain/{table}/{name}/", del_chain).Methods("DELETE")
	router.HandleFunc("/chain/{table}/{name}/", list_chain).Methods("GET")
	router.HandleFunc("/mvchain/{table}/{oldname}/{newname}/", rename_chain).Methods("PUT")
	router.HandleFunc("/jumpchain/{table}/{chain}/{chain_to_jump}/", add_chain_jump).Methods("PUT")
	router.HandleFunc("/jumpchain/{table}/{chain}/{chain_to_jump}/", del_chain_jump).Methods("DELETE")
	router.HandleFunc("/save/", save_rules).Methods("GET")
	router.HandleFunc("/restore/", restore_rules).Methods("PUT")

	loggedRouter := handlers.CombinedLoggingHandler(accessLog, router)

	if *https {
		if ( *cert == "" ) || ( *key == "" ) {
			log.Fatalf("HTTPS true but no cert and key defined")
		} else {
			log.Fatal(http.ListenAndServeTLS(strings.Join([]string{*listen_ip, ":", *listen_port}, ""), *cert, *key, loggedRouter))
		}
	} else {
		log.Fatal(http.ListenAndServe(strings.Join([]string{*listen_ip, ":", *listen_port}, ""), loggedRouter))
	}
}

// GET /save/
func save_rules(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	os.Mkdir("/etc/iptables/",0755)
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
	os.Mkdir(*save_path,0755)

	current_time := time.Now().Local()
	dst_f := []string{*save_path, "rules.v4.", current_time.Format("2006-01-02"), ".", current_time.Format("15-04-05")}
	cmd := exec.Command("cp", "/etc/iptables/rules.v4", strings.Join(dst_f, ""))
	err = cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, strings.Join(dst_f, ""))
}

// GET /restore/{file}
func restore_rules(w http.ResponseWriter, r *http.Request) {
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

func rule_generate(r *http.Request) []string {
	vars := mux.Vars(r)
	var spec_end []string

	if r.URL.Query().Get("sports") != "" {
		spec_end = append(spec_end, "-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		spec_end = append(spec_end,"-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("state") != "" {
		spec_end = append(spec_end, "-m", "state", "--state", r.URL.Query().Get("state"))
	}
	if r.URL.Query().Get("fragment") != "" {
		spec_end = append(spec_end,"-f")
	}
	if r.URL.Query().Get("icmptype") != "" {
		spec_end = append(spec_end,"--icmp-type", r.URL.Query().Get("icmptype"))
	}
	if vars["iface_in"] != "*" {
		spec_end = append(spec_end, "-i", vars["iface_in"])
	}
	if vars["iface_out"] != "*" {
		spec_end = append(spec_end, "-o", vars["iface_out"])
	}
	src_range := strings.Contains(vars["source"], "-")
	dst_range := strings.Contains(vars["destination"], "-")
	rulespecs := []string{"-p", vars["proto"]}
	if src_range {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_32", "", -1))
	} else {
		rulespecs = append(rulespecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if dst_range {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_32", "", -1))
	} else {
		rulespecs = append(rulespecs, "-d", strings.Replace(vars["destination"], "_", "/", -1))
	}
	rulespecs = append(rulespecs, "-j", vars["action"])
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == "LOG" {
			rulespecs = append(rulespecs, "--log-prefix", r.URL.Query().Get("log-prefix"))
	}
	rulespecs = append(rulespecs, spec_end...)
	return rulespecs
}

func CheckPosRules(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string

	line := []string{vars["action"], vars["proto"]}
	if r.URL.Query().Get("fragment") != "" {
		line = append(line, "-f")
	} else {
		line = append(line, "--")
	}
	line = append(line, vars["iface_in"], vars["iface_out"])

	src_range := strings.Contains(vars["source"], "-")
	if src_range {
		line = append(line, "0.0.0.0/0")
	} else {
		source_32 := strings.Contains(vars["source"], "_32")
		if source_32 {
			line = append(line, strings.Replace(vars["source"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["source"], "_", "/", -1))
		}
	}
		
	dst_range := strings.Contains(vars["destination"], "-")
	if dst_range {
		line = append(line, "0.0.0.0/0")
	} else {
		destination_32 := strings.Contains(vars["destination"], "_32")
		if destination_32 {
			line = append(line, strings.Replace(vars["destination"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
		}
	}
	if src_range {
		line = append(line, "source", "IP", "range", strings.Replace(vars["source"], "_32", "", -1))
	}
	if dst_range {
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
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == "LOG" {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil,err
	}
	args := []string{"-t", "filter", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.Wait() {
		args = append(args, "--wait")
	}
	rules, err := ipt.ExecuteList(args)
	if err != nil {
		return nil,err
	}
	for i:= 0; i < len(rules); i++ {
		rulesSlice := strings.Fields(rules[i])
		rulesSliceNoVerb := rulesSlice[3:]
		if reflect.DeepEqual(line, rulesSliceNoVerb) {
			linenumber = append(linenumber, rulesSlice[0])
		}
	}
	return linenumber,nil

}

// PUT /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func add_rules (w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := rule_generate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	vars := mux.Vars(r)
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp_err = ipt.Insert("filter", vars["chain"], position, rulespecs...)
	} else {
		resp_err = ipt.Append("filter", vars["chain"], rulespecs...)
	}
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func del_rules (w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := rule_generate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	vars := mux.Vars(r)
	resp_err = ipt.Delete("filter", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// GET /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func check_rules (w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	rulespecs := rule_generate(r)
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		pos_rules, err := CheckPosRules(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if len(pos_rules) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(pos_rules) != 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if pos_rules[0] == r.URL.Query().Get("position") {
			return
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		vars := mux.Vars(r)
		resp_str, resp_err := ipt.Exists("filter", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
			return
		}
		if !resp_str {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
}

func dnat_generate(r *http.Request) []string {
	vars := mux.Vars(r)
	rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "DNAT", "--to-destination", vars["nat_final"]})
	if r.URL.Query().Get("dport") != "" {
			rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if ( r.URL.Query().Get("nth_every") != "" ) {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}
	return rulespecs
}

func snat_generate(r *http.Request) []string {
	vars := mux.Vars(r)
	rulespecs := append([]string{"-p", vars["proto"], "-o", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "SNAT", "--to-source", vars["nat_final"]})
	if r.URL.Query().Get("dport") != "" {
		rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if ( r.URL.Query().Get("nth_every") != "" ) {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}
	return rulespecs
}

func CheckPosNat(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string
	var line []string

	if vars["action"] == "dnat" {
		line = append(line, "DNAT", vars["proto"], "--", vars["iface"], "*")
	}
	if vars["action"] == "snat" {
		line = append(line, "SNAT", vars["proto"], "--", "*", vars["iface"])
	}
	source_32 := strings.Contains(vars["source"], "_32")
	destination_32 := strings.Contains(vars["destination"], "_32")
	
	if source_32 {
		line = append(line, strings.Replace(vars["source"], "_32", "", -1))
	} else {
		line = append(line, strings.Replace(vars["source"], "_", "/", -1))
	}
	if destination_32 {
		line = append(line, strings.Replace(vars["destination"], "_32", "", -1))
	} else {
		line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
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

	ipt, err := iptables.New()
	if err != nil {
		return nil,err
	}
	args := []string{"-t", "nat", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.Wait() {
		args = append(args, "--wait")
	}
	nats, err := ipt.ExecuteList(args)
	if err != nil {
		return nil,err
	}
	for i:= 0; i < len(nats); i++ {
		natsSlice := strings.Fields(nats[i])
		natsSliceNoVerb := natsSlice[3:]
		if reflect.DeepEqual(line, natsSliceNoVerb) {
			linenumber = append(linenumber, natsSlice[0])
		}
	}
	return linenumber,nil
}

// PUT /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func add_nat (w http.ResponseWriter, r *http.Request) {
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
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var rulespecs []string
	if ( r.URL.Query().Get("nth_every") != "" ) || ( r.URL.Query().Get("nth_packet") != "" ) {
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
	if vars["action"] == "dnat" {
		rulespecs = dnat_generate(r)
	} else if vars["action"] == "snat" {
		rulespecs = snat_generate(r)
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp_err = ipt.Insert("nat", vars["chain"], position, rulespecs...)
	} else {
		resp_err = ipt.Append("nat", vars["chain"], rulespecs...)
	}
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
// DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func del_nat (w http.ResponseWriter, r *http.Request) {
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
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var rulespecs []string
	if ( r.URL.Query().Get("nth_every") != "" ) || ( r.URL.Query().Get("nth_packet") != "" ) {
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
	if vars["action"] == "dnat" {
		rulespecs = dnat_generate(r)
	} else if vars["action"] == "snat" {
		rulespecs = snat_generate(r)
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	resp_err = ipt.Delete("nat", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
// GET /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func check_nat (w http.ResponseWriter, r *http.Request) {
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
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("position") != "" {
		pos_nat, err := CheckPosNat(r)

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if len(pos_nat) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(pos_nat) != 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if pos_nat[0] == r.URL.Query().Get("position") {
			return
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	var rulespecs []string
	if ( r.URL.Query().Get("nth_every") != "" ) || ( r.URL.Query().Get("nth_packet") != "" ) {
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
	if vars["action"] == "dnat" {
		rulespecs = dnat_generate(r)
	} else if vars["action"] == "snat" {
		rulespecs = snat_generate(r)
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	resp_str, resp_err := ipt.Exists("nat", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
	if !resp_str {
		w.WriteHeader(http.StatusNotFound)
	}
}

func raw_generate(r *http.Request) []string {
	vars := mux.Vars(r)
	var	spec_end []string

	if r.URL.Query().Get("sports") != "" {
		spec_end = append(spec_end,"-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		spec_end = append(spec_end,"-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("notrack") != "" {
		spec_end = append(spec_end,"--notrack")
	}
	if (r.URL.Query().Get("tcpflag1") != "") && (r.URL.Query().Get("tcpflag2") != "") && (vars["proto"] == "tcp") {
		tcpflag := []string{"--tcp-flags", r.URL.Query().Get("tcpflag1"), r.URL.Query().Get("tcpflag2")}
		spec_end = append(spec_end,tcpflag...)
	}
	if vars["iface_in"] != "*" {
		spec_end = append(spec_end, "-i", vars["iface_in"])
	}
	if vars["iface_out"] != "*" {
		spec_end = append(spec_end, "-o", vars["iface_out"])
	}
	src_range := strings.Contains(vars["source"], "-")
	dst_range := strings.Contains(vars["destination"], "-")
	rulespecs := []string{"-p", vars["proto"]}
	if src_range {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.Replace(vars["source"], "_32", "", -1))
	} else {
		rulespecs = append(rulespecs, "-s", strings.Replace(vars["source"], "_", "/", -1))
	}
	if dst_range {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.Replace(vars["destination"], "_32", "", -1))
	} else {
		rulespecs = append(rulespecs, "-d", strings.Replace(vars["destination"], "_", "/", -1))
	}
	rulespecs = append(rulespecs, "-j", vars["action"])
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == "LOG" {
		rulespecs = append(rulespecs, "--log-prefix", r.URL.Query().Get("log-prefix"))
	}
	rulespecs = append(rulespecs, spec_end...)
	return rulespecs
}

func CheckPosRaw(r *http.Request) ([]string, error) {
	vars := mux.Vars(r)
	var linenumber []string

	line := []string{vars["action"], vars["proto"], "--"}
	line = append(line, vars["iface_in"], vars["iface_out"])

	src_range := strings.Contains(vars["source"], "-")
	if src_range {
		line = append(line, "0.0.0.0/0")
	} else {
		source_32 := strings.Contains(vars["source"], "_32")
		if source_32 {
			line = append(line, strings.Replace(vars["source"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["source"], "_", "/", -1))
		}
	}

	dst_range := strings.Contains(vars["destination"], "-")
	if dst_range {
		line = append(line, "0.0.0.0/0")
	} else {
		destination_32 := strings.Contains(vars["destination"], "_32")
		if destination_32 {
			line = append(line, strings.Replace(vars["destination"], "_32", "", -1))
		} else {
			line = append(line, strings.Replace(vars["destination"], "_", "/", -1))
		}
	}
	if src_range {
		line = append(line, "source", "IP", "range", strings.Replace(vars["source"], "_32", "", -1))
	}
	if dst_range {
		line = append(line, "destination", "IP", "range", strings.Replace(vars["destination"], "_32", "", -1))
	}
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && vars["action"] == "LOG" {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil,err
	}
	args := []string{"-t", "raw", "-vnL", vars["chain"], "--line-numbers"}
	if ipt.Wait() {
		args = append(args, "--wait")
	}
	raws, err := ipt.ExecuteList(args)
	if err != nil {
		return nil,err
	}
	for i:= 0; i < len(raws); i++ {
		rawsSlice := strings.Fields(raws[i])
		rawsSliceNoVerb := rawsSlice[3:]
		if reflect.DeepEqual(line, rawsSliceNoVerb) {
			linenumber = append(linenumber, rawsSlice[0])
		}
	}
	return linenumber,nil		
}

// PUT /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func add_raw (w http.ResponseWriter, r *http.Request) {
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
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := raw_generate(r)
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp_err = ipt.Insert("raw", vars["chain"], position, rulespecs...)
	} else {
		resp_err = ipt.Append("raw", vars["chain"], rulespecs...)
	}
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
// DELTE /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func del_raw (w http.ResponseWriter, r *http.Request) {
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
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := raw_generate(r)
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	resp_err = ipt.Delete("raw", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
// GET /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func check_raw (w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := raw_generate(r)
	if ipt.Wait() {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		if r.URL.Query().Get("tcpflag1") != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "tcpflag and position not compatible")
			return
		}
		if r.URL.Query().Get("tcpflag2") != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "tcpflag and position not compatible")
			return
		}
		pos_raw, err := CheckPosRaw(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if len(pos_raw) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(pos_raw) != 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if pos_raw[0] == r.URL.Query().Get("position") {
			return
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		vars := mux.Vars(r)
		resp_str, resp_err := ipt.Exists("raw", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
			return
		}
		if !resp_str {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
}


// PUT /chain/{table}/{name}/ 
func add_chain (w http.ResponseWriter, r *http.Request) {
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
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		resp_err = ipt.NewChainWithWait(vars["table"], vars["name"])
	} else {
		resp_err = ipt.NewChain(vars["table"], vars["name"])
	}
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// DELETE /chain/{table}/{name}/
func del_chain (w http.ResponseWriter, r *http.Request) {
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
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		// Clear chain before delete
		resp_err = ipt.ClearChainWithWait(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
		// Delete chain
		resp_err = ipt.DeleteChainWithWait(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	} else {
		// Clear chain before delete
		resp_err = ipt.ClearChain(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
		// Delete chain
		resp_err = ipt.DeleteChain(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	}
}

// GET /chain/{table}/{name}/
func list_chain (w http.ResponseWriter, r *http.Request) {
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

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		resp_str, resp_err := ipt.ListWithWait(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
		
		for i:= 0; i < len(resp_str); i++ {
			fmt.Fprintln(w, resp_str[i])
		}
	} else {
		resp_str, resp_err := ipt.List(vars["table"], vars["name"])
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
		
		for i:= 0; i < len(resp_str); i++ {
			fmt.Fprintln(w, resp_str[i])
		}
	}
}

// PUT /mvchain/{table}/{oldname}/{newname}/
func rename_chain (w http.ResponseWriter, r *http.Request) {
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

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.Wait() {
		resp_err = ipt.RenameChainWithWait(vars["table"], vars["oldname"], vars["newname"])
	} else {
		resp_err = ipt.RenameChain(vars["table"], vars["oldname"], vars["newname"])
	}
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// PUT /jumpchain/{table}/{chain}/{chain_to_jump}/
func add_chain_jump (w http.ResponseWriter, r *http.Request) {
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

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	rulespec := []string{"-j", vars["chain_to_jump"]}
	resp_err = ipt.AppendUnique(vars["table"], vars["chain"], rulespec...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// DELETE /jumpchain/{table}/{chain}/{chain_to_jump}/
func del_chain_jump (w http.ResponseWriter, r *http.Request) {
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

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	rulespec := []string{"-j", vars["chain_to_jump"]}
	resp_err = ipt.Delete(vars["table"], vars["chain"], rulespec...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
