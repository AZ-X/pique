![CodeQL](https://github.com/AZ-X/dnsslim/workflows/CodeQL/badge.svg) ![go builder verifier](https://github.com/AZ-X/dnsslim/workflows/go%20builder(verifier)/badge.svg)

# Alternative (slimmer) client approach to [miekg/dns](https://github.com/miekg/dns)

> ~~Less is more~~.

Complete and usable DNS library. All Resource Records are supported, including the DNSSEC types.
It follows a lean and mean philosophy. If there is stuff you should know as a DNS programmer there
isn't a convenience function for it. 

Server side and client side programming is NOT supported

This repository tries to keep the "master" branch as `sane` as possible and at the bleeding edge of standards,
avoiding breaking changes whoever `responsible`. 

# Goals

* Slim;

# Users

A not-so-up-to-date-list-that-may-be-actually-current:

* https://github.com/AZ-X/pique [(using this trimmed version of miekg/dns)](https://github.com/AZ-X/pique/tree/master/vendor/github.com/miekg/dns)

Send pull request if you want to be listed here.

# Features

* DNSSEC: signing, validating and key generation for DSA, RSA, ECDSA and Ed25519
* EDNS0, NSID, Cookies
* AXFR/IXFR
* TSIG, SIG(0)
* DNS name compression

Have fun!

AZ-X
2021

# Building

This library uses Go modules and uses semantic versioning. Building is done with the `go` tool, so
the following should work:

    go get github.com/AZ-X/dns
    go build github.com/AZ-X/dns

