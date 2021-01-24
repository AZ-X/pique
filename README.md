![CodeQL](https://github.com/AZ-X/pique/workflows/CodeQL/badge.svg)![repique_release](https://github.com/AZ-X/pique/workflows/repique_release/badge.svg)

# Intro: What's pique or repique

## Repique is an advanced DNS stub which can run on different OS such as Windows, Linux, OpenWRT.

## Repique is unique in the world because:

- All DNS queries forwarded by repique are encrypted and secured as following top consumable standard.
- The forwarding regulation of repique are extremely dynamic and flexible for self-hosted multiple listeners and upstreams.
- The configuration of clockes, caches and patterns of repique can be ad hoc reloaded on Windows anytime unlimited.
- The size(6MiB) of repique's binary file are much smaller than the rest of existing go program which has supported 3+ encryption protocols.
- Repique is the only public golang program leveraging nested socks5/tcp/udp and http(s) proxy.
- Main program is called "Repique" while its repository name is "Pique", which just creates foo-bar towards golang.
- [There is an additional awesome standalone GUI tooling in combination with repique, check it.](https://github.com/AZ-X/WPF-GO-dnscrypt-proxy-md/wiki)

**pique** /piːk/

**repique** /ʁə.pik/

> The words "pique" and "repique" are of Spanish origin

> Although it often scores poorly, it is usually advantageous to declare it to prevent the opponent from scoring pique or repique, despite the tactical disadvantage of giving information to the opponent

# ![repique dnscrypt-proxy-r2-legacy](https://github.com/AZ-X/MEDIA/blob/master/PNG/RD.png?raw=true)


# Overview

## Why use pique or repique

Repique acts out an unifiable key point of Internet of Things - DNS Privacy and Confidence.  
Be an advancer of IoT, repique embraces aspects of Freedom, Privacy and Security.  
Nowadays people like using their preferred DNS services to maximize the interests of personal IoT and business network.
An illuminated perspective of new DNS infrastucture is representing as multiple upstreams, multiple encryption protocols and multiple interventions.
There are so many open source applications of DNS client/server that people usually can't distinguish difference between each other.
They often confuse a DNS stub with a DNS server running locally. Even the authors of building DNS toolset, they are misleading the fundamental functionality and features of client/server.  
For example:
- `cache.c` in dnsmasq by Simon Kelley uses 2K-LOCs(source lines of code) to maintain different type of DNS queries while others pseudo 'server' applications only delegate its functionality to vendors or create a rough one.
- `network.c` in dnsmasq uses 2K-LOCs to coordinate sfd of socket and interfaces while others pseudo 'server' applications only delegate its functionality to vendors or create a rough one.
- *ACCESS-CONTROL, MEMORY-CONTROL, THREADS-CONTROL,CACHE-CONTROL, SOCKET OPTION* in unbound by NLnetLabs are more detailed than others pseudo 'server' applications.

It sights a lack of creativity of DNS toolset mostly and these senseless users are used to pseudo newcome and speaking yogurt.  
The fact is repique never aims at being a DNS server application so that it never performs overhead design or pseudo implementation.  
However repique did most DNS stub never did, a powerful, dynamic and flexible program with interoperability to strong encryption protocols and routines to synthetic data.

Repique can share cache and patterns between multiple listeners or on the contrary, isolate them as independence.  
Repique can create nested groups for upstreams as well as tags for extra definition of upstreams.  
Repique can use regular expressions to dispatch queries to groups, tags and listeners.  
Repique has less explicit fingerprints and interaction behaviors than the rest of applications.  
Repique forces TLS to fix on **version 1.3** and therefore **bypasses** https 1.1.  
Repique uses same ordered cipher suites no matter of what hardware features running on and has **discarded** `TLS_AES_128_GCM_SHA256` from v1.3 suites.  
Repique uses compatible upstreams definitions with dnscrypt-proxy and compatible routines with Acrylic DNS.  
Repique is the only alternative golang implementation conform to dnscrypt protocol.  
Repique goes beyond other stubs by implementing preload functions and various cache procedures.(See [example](https://github.com/AZ-X/pique/blob/master/examples/configuration/black_cloaking_routine.txt.example))

## Who use pique or repique

- People who take care of 'DNS Privacy'.
- People who desire an inclusive DNS stub.
- people who start prioritizing digital freedom, privacy and security across convenience and cost.
- People who accept/cognize possible sophisticated analysis on encryption protocols as well inner/outer states by public servers, non-agreement front/back-end of services and mid hops.
- People who understand the first principle of **Zero Trust**.
- People who practise **Zero Trust** security with open source contributions and vendors.
- People who have a background in computer science and normal IQ able to produce exact regular expressions for repique
- People who study golang or cryptoanalysis.
- People who can foresee the future form of IoT evolvement.

### Comparison between repique and dnscrypt-proxy

1. Rewritten crypto functions
1. Rewritten all protocols baseline
1. Improved debug info so as to achieve principal stage of module based iteration methodology
1. Improved flows and data handling
1. Improved general design of common CLI program
1. Strict & Small & Smart

### Comparison between repique and dnsmasq/pihole-FTL

Pihole-FTL is an enhanced(it's called coupling) dnsmasq copy with database, lua scripting, DHCP-discover and signals/regex support.  
Pihole-FTL is a fat variation of dnsmasq even has a set of Telnet API.  
Pihole-FTL/dnsmasq is a regular DNS server comparing to repique.  
Pihole-FTL/dnsmasq doesn't support encryption protocols.  
It is always recommended to use repique combining with a DNS server if hosting on a capable device.

### Comparison between repique and pihole-MassDNS

Repique can run on different OS while MassDNS is designed to run on Linux.

### Comparison between repique and CoreDNS

> CoreDNS is a DNS server that chains plugins

Repique is a DNS stub that discarded plugins  
If using CoreDNS as a forwarder, applicable size is `coredns_1.8.1_windows_amd64.tgz` 12.4 MB (extracted `coredns.exe` 41.0 MB)

### Comparison between repique and Acrylic DNS

Acrylic is a DNS stub built with Delphi 7.  
Repique is built with golang fresh version.  
Repique can build with consistency on any machine and check its fidelity.  
Acrylic doesn't support encryption protocols and complex routines.  

### Comparison between repique and dnsdist(PowerDNS)

PowerDNS is similar to dnsmasq nevertheless its cryptographic primitives take from OpenSSL and dnsmasq uses Nettle.  
PowerDNS has Built-in Webserver and HTTP API that repique never wants to implement.  
PowerDNS doesn't support encryption protocols and complex routines. 

### Comparison between repique and AdGuardHome

If using AdGuardHome as a forwarder, applicable size is `AdGuardHome_windows_amd64.zip` 8.31 MB  
AdGuard comes with a beautiful dashboard and ad-block features.  
There is no complex routines or strict TLS when using AdGuardHome.   
It is easy to compare memory usage of both; the conclusion is clear: only repique can run on limited hardware e.g. a mips soc with small mem.

### Comparison between repique and m13253-dns-over-https/routedns/the others DNS applications

There is no complex routines or strict TLS when using others implementation.  
There is no dnscrypt protocol support when using others implementation.  


## Getting Started

### Recommend Setup Scenarios:

- Work with DNS client:  
running on the supported OS; using the default DNS client by OS; configurate repique as the first upstream resolver.
- Work with DNS server:  
running on the supported OS; using any DNS server preferred; configurate forwarding rule to repique.

### Installation



:arrow_double_down::arrow_double_down::arrow_double_down: old description

### [Download the latest release] coming soon maybe tomorrow


## Server Name Indication :notebook_with_decorative_cover:

:ghost: rfc3546 :ghost: draft-ietf-tls-rfc4366-bis-12 :ghost: rfc6066  
```c#
'BCI/RSA Security/Transactionware/Vodafone/Stellar Switches/Huawei USA'
```
## Autobiography

[discussions...](https://github.com/AZ-X/pique/discussions/11)

:arrow_double_down::arrow_double_down::arrow_double_down: old snapshot when middle ages

# ![repique dnscrypt-proxy-r2-legacy](https://github.com/AZ-X/MEDIA/blob/master/PNG/dnscrypt-proxy-r2-mips.png?raw=true)




