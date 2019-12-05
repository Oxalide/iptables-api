# iptables-api


See [![new_repository](https://img.shields.io/badge/github-jeremmfr%2Fiptables--api-critical)](https://github.com/jeremmfr/iptables-api) for next commits/releases

#
[![GoDoc](https://godoc.org/github.com/jeremmfr/iptables-api?status.svg)](https://godoc.org/github.com/jeremmfr/iptables-api) [![Go Report Card](https://goreportcard.com/badge/github.com/jeremmfr/iptables-api)](https://goreportcard.com/report/github.com/jeremmfr/iptables-api)

Create API REST for iptables command

Compile:
--------
export GO111MODULE=on  
go build -o iptables-api

Run:
----
    ./iptables-api -h
	Usage of /root/iptables-api:
	  -cert string
	        file of certificat for https
	  -htpasswd string
	        htpasswd file for login:password
	  -https
	        https = true or false
	  -ip string
	        listen on IP (default "127.0.0.1")
	  -key string
	        file of key for https
	  -log string
	        file for access log (default "/var/log/iptables-api.access.log")
	  -port string
	        listen on port (default "8080")
	  -save_path string
			path for backups => /save (default "var/backups/iptables-api/")

    ./iptables-api -https -ip=192.168.0.1 -port=8443 -log=/var/log/iptables-api.access.log -cert=cert.pem -key=key.pem -htpasswd=/root/.htpasswd

API List :
---------

**Rules:**

Test,Add,Del iptables rule in table filter with the parameters

	GET/PUT/DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&state=XXXX&fragment=true&icmptype=XXXX&log-prefix=XXXXX

	with for source and destination _ instead / : 10.0.0.0_8 or range 10.0.0.0-10.255.0.0_32
	log-prefix only if action = LOG

**Nat:**

Test,Add,Del iptables rule in table nat with the parameters

	GET/PUT/DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00&except=true

	with for source and destination _ instead / : 10.0.0.0_8

**Raw:**

Test,Add,Del iptables rule in table raw with the parameters

	GET/PUT/DELETE /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true&log-prefix=XXXXX

	with for source and destination _ instead / : 10.0.0.0_8 or range 10.0.0.0-10.255.0.0_32
	log-prefix only if action = LOG

**Chain:**

Test,Add,Del chain with the parameters

	GET/PUT/DELETE /chain/{table}/{name}/

Rename chain with the parameters

	PUT /mvchain/{table}/{oldname}/{newname}/

**Save:**

iptables-save > /etc/iptables/rules.v4 && cp /etc/iptables/rules.v4 /var/backups/iptables-api/rules.v4.2006-01-02.15-04-05

	GET /save/

**Restore:**

iptables-restore $file

	PUT /restore/{file}
