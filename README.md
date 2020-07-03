# ![dnscrypt-proxy-r2](https://github.com/AZ-X/MEDIA/blob/master/PNG/RD.png?raw=true)


## Overview

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://github.com/AZ-X/dnscrypt-proxy-r2/protocol/DNSCRYPT-V2-PROTOCOL.txt), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.txt) and [Anonymized DNSCrypt](https://github.com/AZ-X/dnscrypt-proxy-r2/protocol/ANONYMIZED-DNSCRYPT.txt).

Less than 7mb for single file size

Better than original one comparing to most aspect


## [Download the latest release] coming soon maybe tomorrow

Available as source code and pre-built binaries for most operating systems and architectures (see below).

## Features

* DNS traffic encryption and authentication. Supports DNS-over-HTTPS (DoH) using TLS 1.3, DNSCrypt and Anonymized DNS
* Client IP addresses can be hidden using Tor, SOCKS proxies or Anonymized DNS relays
* DNS query monitoring, with separate log files for regular and suspicious queries(no answers)
* Filtering: block ads, malware, and other unwanted content(more complicated)
* Time-based filtering, with a flexible weekly schedule(removed)
* Transparent redirection of specific domains to specific resolvers
* DNS caching, to reduce latency and incompatible with DNSSEC
* Local IPv6 blocking to reduce latency on IPv4-only networks
* Load balancing: we never have such things
* Cloaking: like a `HOSTS` file on steroids, that can return preconfigured addresses for specific names, or resolve and return the IP address of other names. This can be used for local development as well as to enforce safe search results on Google, Yahoo, DuckDuckGo and Bing
* Automatic background updates of resolvers lists(removed)
* Can force outgoing connections to use TCP
* Compatible with DNSSEC, NOT ture unless you only use certain DOH Server
* We know what's called "TLS Encrypted Client Hello"

## Pre-built binaries

Up-to-date, pre-built binaries are selected for:


* Linux/mips
* Linux/x86_64
* Windows 64 bit

How to use these files, as well as how to verify their signatures, are documented in the 
[additional tooling](https://github.com/AZ-X/WPF-GO-dnscrypt-proxy-md/wiki).

## Contributors

### Code Contributors

Welcome to new reworking project aka R2 version
