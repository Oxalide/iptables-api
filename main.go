package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jeremmfr/go-iptables/iptables"
)

const (
	//
	v6                iptables.Protocol = iota + 1
	dnatAct           string            = "dnat"
	snatAct           string            = "snat"
	logAct            string            = "LOG"
	trueStr           string            = "true"
	tcpStr            string            = "tcp"
	SYNStr            string            = "SYN"
	defaultFlagsMask  string            = "FIN,SYN,RST,ACK"
	defaultFlagsMask2 string            = "SYN,RST,ACK,FIN"
)

var (
	respErr      error
	htpasswdfile *string
	savePath     *string
)

func main() {
	listenIP := flag.String("ip", "127.0.0.1", "listen on IP")
	listenPort := flag.String("port", "8080", "listen on port")
	https := flag.Bool("https", false, "https = true or false")
	cert := flag.String("cert", "", "file of certificat for https")
	key := flag.String("key", "", "file of key for https")
	accessLogFile := flag.String("log", "/var/log/iptables-api.access.log", "file for access log")
	htpasswdfile = flag.String("htpasswd", "", "htpasswd file for login:password")
	savePath = flag.String("savepath", "/var/backups/iptables-api/", "path for backups file on /save")

	flag.Parse()

	// accesslog file open
	accessLog, err := os.OpenFile(*accessLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open access log: %s", err)
	}

	// create router
	router := mux.NewRouter().StrictSlash(true)

	// ipv4 api
	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", addRules).Methods("PUT")
	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", delRules).Methods("DELETE")
	router.HandleFunc("/rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", checkRules).Methods("GET")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", addRaw).Methods("PUT")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", delRaw).Methods("DELETE")
	router.HandleFunc("/raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", checkRaw).Methods("GET")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", addNat).Methods("PUT")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", delNat).Methods("DELETE")
	router.HandleFunc("/nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", checkNat).Methods("GET")
	router.HandleFunc("/chain/{table}/{name}/", addChain).Methods("PUT")
	router.HandleFunc("/chain/{table}/{name}/", delChain).Methods("DELETE")
	router.HandleFunc("/chain/{table}/{name}/", listChain).Methods("GET")
	router.HandleFunc("/mvchain/{table}/{oldname}/{newname}/", renameChain).Methods("PUT")
	router.HandleFunc("/save/", saveRules).Methods("GET")
	router.HandleFunc("/restore/", restoreRules).Methods("PUT")

	// ipv6 api
	router.HandleFunc("/rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", addRulesV6).Methods("PUT")
	router.HandleFunc("/rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", delRulesV6).Methods("DELETE")
	router.HandleFunc("/rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", checkRulesV6).Methods("GET")
	router.HandleFunc("/raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", addRawV6).Methods("PUT")
	router.HandleFunc("/raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", delRawV6).Methods("DELETE")
	router.HandleFunc("/raw_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/", checkRawV6).Methods("GET")
	router.HandleFunc("/nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", addNatV6).Methods("PUT")
	router.HandleFunc("/nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", delNatV6).Methods("DELETE")
	router.HandleFunc("/nat_v6/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/", checkNatV6).Methods("GET")
	router.HandleFunc("/chain_v6/{table}/{name}/", addChainV6).Methods("PUT")
	router.HandleFunc("/chain_v6/{table}/{name}/", delChainV6).Methods("DELETE")
	router.HandleFunc("/chain_v6/{table}/{name}/", listChainV6).Methods("GET")
	router.HandleFunc("/mvchain_v6/{table}/{oldname}/{newname}/", renameChainV6).Methods("PUT")
	router.HandleFunc("/save_v6/", saveRulesV6).Methods("GET")
	router.HandleFunc("/restore_v6/", restoreRulesV6).Methods("PUT")

	loggedRouter := handlers.CombinedLoggingHandler(accessLog, router)

	if *https {
		if (*cert == "") || (*key == "") {
			log.Fatalf("HTTPS true but no cert and key defined")
		} else {
			log.Fatal(http.ListenAndServeTLS(strings.Join([]string{*listenIP, ":", *listenPort}, ""), *cert, *key, loggedRouter))
		}
	} else {
		log.Fatal(http.ListenAndServe(strings.Join([]string{*listenIP, ":", *listenPort}, ""), loggedRouter))
	}
}
