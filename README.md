# ![dnscrypt-proxy-r2](https://github.com/AZ-X/MEDIA/blob/master/PNG/RD.png?raw=true)

# ![dnscrypt-proxy-r2](https://github.com/AZ-X/MEDIA/blob/master/PNG/dnscrypt-proxy-r2-mips.png?raw=true)


## Autobiography

This project started from [#issues/932](https://github.com/DNSCrypt/dnscrypt-proxy/issues/932) when I went through full issues list (Not just opened)

I caught up with a quote in that issue 'the best option is to change these, and you already found how to do it :)'

Since then I patched my own version since the author encouraged these alternative changes

I don't want to rewrite everything, it's boring

The more I patched it the more dull idea became volatile

Finally I found myself become partner of it, I learned golang in deep because of it and notepad++ is the only tooling reflecting these source code for me on Windows

I decide to share a whole of these reformed code for community

This is a show case of AMAZING project




## Overview

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://github.com/AZ-X/dnscrypt-proxy-r2/blob/master/dnscrypt-proxy/protocol/DNSCRYPT-V2-PROTOCOL.txt), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.txt) and [Anonymized DNSCrypt](https://github.com/AZ-X/dnscrypt-proxy-r2/blob/master/dnscrypt-proxy/protocol/ANONYMIZED-DNSCRYPT.txt).

Less than 7mb for go binary size

Better than original one comparing to most aspect


## [Download the latest release] coming soon maybe tomorrow

Available as source code and pre-built binaries for most operating systems and architectures (see below).


## Comparison between R2 and dnscrypt-proxy

### Pros:

1.	Improved debug info – principal stage of a program
2.	Improved configuration to an HTTPS2 interface 
3.	Enable multiple IPs to same domain (DoH/DoT)
4.	Improved flows of data handling
5.	Improved crypto functions
6.	Improved general design
7.	Improved usage of relays
8.	Strict & Small & Smart
9.	Aimed at improving use on Ath79 devices

### Cons:

1.	Removed Windows Services feature (security concern)
2.	Removed Linux systemd feature (I don’t use it)
3.	Removed Windows Event Logs feature (security concern)
4.	Removed weekly schedules feature (I don’t think people will use it)
5.	Removed Mac support (I don’t  have a powerful Mac device to run test on	:slightly_frowning_face:)
6.	Removed Android support (I don’t agree a Non-GUI app and poor integration for Android)


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
