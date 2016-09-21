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

	"github.com/coreos/go-iptables/iptables"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

var (
	resp_err error
)

func main() {
	// check arguments
	if len(os.Args) < 4 {
		fmt.Println("usage: api-iptables <IP> <port> <logfile>")
		return
	}
	// arguments to var
	listen_ip := []string{os.Args[1], os.Args[2]}
	accessLogFile := flag.String("log", os.Args[3], "Access log file")

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
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", add_nat).Methods("PUT")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", del_nat).Methods("DELETE")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", check_nat).Methods("GET")
	router.HandleFunc("/chain/{table}/{name}/", add_chain).Methods("PUT")
	router.HandleFunc("/chain/{table}/{name}/", del_chain).Methods("DELETE")
	router.HandleFunc("/chain/{table}/{name}/", list_chain).Methods("GET")
	router.HandleFunc("/mvchain/{table}/{oldname}/{newname}/", rename_chain).Methods("PUT")
	router.HandleFunc("/save/", save_rules).Methods("GET")
	router.HandleFunc("/restore/", restore_rules).Methods("PUT")

	loggedRouter := handlers.CombinedLoggingHandler(accessLog, router)

	log.Fatal(http.ListenAndServe(strings.Join(listen_ip, ":"), loggedRouter))
}

// GET /save/
func save_rules(w http.ResponseWriter, r *http.Request) {
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
	os.Mkdir("/root/filter/archives/",0755)

	current_time := time.Now().Local()
	dst_f := []string{"/root/filter/archives/rules.v4.", current_time.Format("2006-01-02"), ".", current_time.Format("15-04-05")}
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
	err := exec.Command("iptables-restore", r.URL.Query().Get("file")).Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// PUT /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func add_rules (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_sports []string
	var spec_dports []string

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if r.URL.Query().Get("sports") != "" {
		spec_sports = []string{"-m", "multiport", "--sports", r.URL.Query().Get("sports")}
	}
	if r.URL.Query().Get("dports") != "" {
		spec_dports = []string{"-m", "multiport", "--dports", r.URL.Query().Get("dports")}
	}
	spec_end := append(spec_sports,spec_dports...)
	rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface_in"], "-o", vars["iface_out"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", vars["action"]}, spec_end...)

	resp_err = ipt.Append("filter", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func del_rules (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_sports []string
	var spec_dports []string

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	if r.URL.Query().Get("sports") != "" {
		spec_sports = []string{"-m", "multiport", "--sports", r.URL.Query().Get("sports")}
	}
	if r.URL.Query().Get("dports") != "" {
		spec_dports = []string{"-m", "multiport", "--dports", r.URL.Query().Get("dports")}
	}
	spec_end := append(spec_sports,spec_dports...)
	rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface_in"], "-o", vars["iface_out"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", vars["action"]}, spec_end...)
	
	resp_err = ipt.Delete("filter", vars["chain"], rulespecs...)
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// GET /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func check_rules (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_sports []string
	var spec_dports []string

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("sports") != "" {
		spec_sports = []string{"-m", "multiport", "--sports", r.URL.Query().Get("sports")}
	}
	if r.URL.Query().Get("dports") != "" {
		spec_dports = []string{"-m", "multiport", "--dports", r.URL.Query().Get("dports")}
	}
	spec_end := append(spec_sports,spec_dports...)
	rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface_in"], "-o", vars["iface_out"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", vars["action"]}, spec_end...)

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

// PUT /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func add_nat (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_dports []string
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if vars["action"] == "dnat" {
		if r.URL.Query().Get("dport") != "" {
			spec_dports = []string{"--dport",  r.URL.Query().Get("dport")}
		}
		rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "DNAT", "--to-destination", vars["nat_final"]}, spec_dports...)

		resp_err = ipt.Append("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	} else if vars["action"] == "snat" {
		rulespecs := append([]string{"-p", vars["proto"], "-o", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "SNAT", "--to-source", vars["nat_final"]})
		resp_err = ipt.Append("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

// DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func del_nat (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_dports []string
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if vars["action"] == "dnat" {
		if r.URL.Query().Get("dport") != "" {
			spec_dports = []string{"--dport",  r.URL.Query().Get("dport")}
		}
		rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "DNAT", "--to-destination", vars["nat_final"]}, spec_dports...)

		resp_err = ipt.Append("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	} else if vars["action"] == "snat" {
		rulespecs := append([]string{"-p", vars["proto"], "-o", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "SNAT", "--to-source", vars["nat_final"]})
		resp_err = ipt.Delete("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

// GET /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func check_nat (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var spec_dports []string
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if vars["action"] == "dnat" {
		if r.URL.Query().Get("dport") != "" {
			spec_dports = []string{"--dport",  r.URL.Query().Get("dport")}
		}
		rulespecs := append([]string{"-p", vars["proto"], "-i", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "DNAT", "--to-destination", vars["nat_final"]}, spec_dports...)

		resp_str, resp_err := ipt.Exists("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
	}
		if !resp_str {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else if vars["action"] == "snat" {
		rulespecs := append([]string{"-p", vars["proto"], "-o", vars["iface"], "-s", strings.Replace(vars["source"], "_", "/", -1), "-d", strings.Replace(vars["destination"], "_", "/", -1), "-j", "SNAT", "--to-source", vars["nat_final"]})
		resp_str, resp_err := ipt.Exists("nat", vars["chain"], rulespecs...)
		if resp_err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, resp_err)
		}
		if !resp_str {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

// PUT /chain/{table}/{name}/ 
func add_chain (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp_err = ipt.NewChain(vars["table"], vars["name"])
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// DELETE /chain/{table}/{name}/
func del_chain (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	
	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp_err = ipt.DeleteChain(vars["table"], vars["name"])
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}

// GET /chain/{table}/{name}/
func list_chain (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp_str, resp_err := ipt.List(vars["table"], vars["name"])
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
	
	for i:= 0; i < len(resp_str); i++ {
		fmt.Fprintln(w, resp_str[i])
	}
}

// PUT /mvchain/{table}/{oldname}/{newname}/
func rename_chain (w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp_err = ipt.RenameChain(vars["table"], vars["oldname"], vars["newname"])
	if resp_err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, resp_err)
	}
}
