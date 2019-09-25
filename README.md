# asa-ipsec-go
This script allows you to generate policy based tunnel configurations for the Cisco ASA platform.

## Prerequisites 

* Cisco ASA 8.4 or newer
* Go

## Instructions

Clone this repository to your workstation.

Fill out the CSV forms located in the root of the repo.

Run the ipsec program to generate the code:

`go run ipsec.go`

Password Generator forked from: https://github.com/sethvargo/go-password

It can be installed like this:

`$ go get -u github.com/sethvargo/go-password/password`

Optionally, you can build `ipsec.go` into an executable:

`go build ipsec.go`