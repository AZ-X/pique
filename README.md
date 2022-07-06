![CodeQL](https://github.com/AZ-X/pique/workflows/CodeQL/badge.svg)![repique_release_go1.15](https://github.com/AZ-X/pique/workflows/repique_release_go1.15/badge.svg)[![Gitter](https://badges.gitter.im/repique/community.svg)](https://gitter.im/repique/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

![hash pe 1.15](https://byob.yarr.is/AZ-X/pique/repique115pe)
![hash elf 1.15](https://byob.yarr.is/AZ-X/pique/repique115elf)

# Intro: What's pique or repique

> It's not DNS...  
> There's no way it was DNS...  
> It was DNS.  
> -- SSBroski

> Here’s my favorite example.  
> Once upon a time, if you clicked on the website link for The New York Times, you were exposed to malware.  
> And the reason is that if you ask for the front page of The New York Times, there are ads inserted, and they have been inserted by ad brokers who take them from whoever wants to pay for them.  
> And in some cases, it’s people who want to spread malware.  
> The little ad links are one of the famous ways to spread malware, and it’s not something I’ve ever clicked on, but it’s included.  
> So I have a certain amount of hygiene that I follow about what I click on, but in reality, I really rely upon additional filtering behind the scenes to keep me out of harm’s way.  
> So I have blacklists.  
> -- Paul Mockapetris (Dr. PM)

> The other thing is that Cloudflare hosts content for far-right US organizations, militant groups, torrent sites, and sites that spread malware.  
> No matter what your political philosophy is, Cloudflare is hosting somebody that you find really repugnant.  
> So using them to filter your DNS doesn’t seem to me to be a good idea, because they’re not going to filter out content that they’re serving themselves.  
> -- Dr. PM

> A lot of people view this (DNS filtering default done by the ISP) as censorship.  
> Once upon a time, people thought that spam filtering was dangerous because censoring email was evil, and so forth.  
> Today, I don’t think there’s anybody who uses email that doesn’t use such filtering mechanisms.  
> Likewise, I don’t think anybody should be using DNS without having filtering mechanisms.  
> -- Dr. PM

## Repique is an advanced DNS stub which can run on different OS such as Windows, Linux, OpenWRT.

### ![golang 1.18.2](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/repique1.18.2.png?raw=true)

### ![openwrt](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/fin.PNG?raw=true)

## Repique is unique in the world because:

- All DNS queries forwarded by repique are encrypted and secured as following top consumable standard.
- The forwarding regulation of repique are extremely dynamic and flexible for self-hosted multiple listeners and upstreams.
- The configuration of clockes, caches and patterns of repique can be ad hoc reloaded on Windows anytime unlimited.
- The all sizes(6MiB) of repique's binary files are much smaller than the rest of existing go program which has supported 3+ encryption protocols.
- Repique is the only public golang program leveraging nested socks5/tcp/udp and http(s) proxy.
- Main program is called "Repique" while its repository name is "Pique", which just creates foo-bar towards golang.
- [There is an additional awesome standalone GUI tooling in combination with repique, check it.](https://github.com/AZ-X/WPF-GO-dnscrypt-proxy-md/wiki)

## Repique Ver.2.2.x highlights:

- Support Secure DNS bootstrap.
- Materials as rotation of public key of dnscrypt protocol or multiple ip addresses of hostname/domain name of DoT/DoH protocol can be persisted in a specified textual file.
- Materials can be loaded on startup to fulfill needs.
- Quiet mode for repique increases flexibility that can keep serving without performing any additional exchange(network activity) on startup.
- Implement well known tags for individual timeouts, http method, etc.

# ![repique32](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/repique32.PNG?raw=true)
Illustration of running repique on a laptop manufactured in Y2008 which unbelievably boots to Windows for seconds without hibernate.  
Illustration of memory cost, not as good as other swift programs, but acceptable to most of hardwares.

**pique** /piːk/

**repique** /ʁə.pik/

> The words "pique" and "repique" are of Spanish origin

> Although it often scores poorly, it is usually advantageous to declare it to prevent the opponent from scoring pique or repique, despite the tactical disadvantage of giving information to the opponent

# ![repique dnscrypt-proxy-r2-legacy](https://github.com/AZ-X/MEDIA/blob/master/PNG/RD.png?raw=true)


# Overview

## Why use pique or repique

Repique acts out a unifiable key point of Internet of Things - DNS Privacy and Confidence.  
Be an advancer of IoT, repique embraces aspects of Freedom, Privacy and Security.  
Nowadays people like using their preferred DNS services to maximize the interests of personal IoT and business network.
An illuminated perspective of new DNS infrastucture is representing as multiple upstreams, multiple encryption protocols and multiple interventions.
There are so many open source applications of DNS client/server that people usually can't distinguish difference between each other.
They often confuse a DNS stub with a DNS server running locally. Even the authors of building DNS toolset, they are misleading the fundamental functionality and features of client/server.  
For example:
- `cache.c` in dnsmasq by Simon Kelley uses 2K-LOCs(source lines of code) to maintain different type of DNS queries while others pseudo 'server' applications only delegate its functionality to vendors or create a rough one.
- `network.c` in dnsmasq uses 2K-LOCs to coordinate sfd of socket and interfaces while others pseudo 'server' applications only delegate its functionality to vendors or create a rough one.
- *ACCESS-CONTROL, MEMORY-CONTROL, THREADS-CONTROL,CACHE-CONTROL, SOCKET OPTION* in unbound by NLnetLabs are more detailed than others pseudo 'server' applications.

Now, everybody knows the story in year 2020.
> DNSpooq: Cache Poisoning and RCE in Popular DNS Forwarder (`rfc1035.c 2K-LOCs`)
> DNSpooq `demonstrates` that DNS implementations are still insecure, even today, 13 years after the last major attack was described.

|CVE|Impact|
|--|--|
|CVE-2020-25684|DNS Cache Poisoning|
|CVE-2020-25685|DNS Cache Poisoning|
|CVE-2020-25686|DNS Cache Poisoning|
|CVE-2020-25681|Remote Code Execution, Denial of Service|
|CVE-2020-25682|Remote Code Execution, Denial of Service|
|CVE-2020-25683|Remote Code Execution, Denial of Service|
|CVE-2020-25687|Remote Code Execution, Denial of Service|

> In a bit of irony, in order for a device to be affected by the four buffer overflow vulnerabilities, the DNSSEC feature must be enabled.
> Devices with DNSSEC disabled would NOT be affected by the buffer overflow flaws.
> However, JSOF notes it is important to enable DNSSEC as it is used to prevent cache poisoning attacks.

> DNS is an Internet-critical protocol whose security greatly affect the security of Internet users.
> In this paper, JSOF presented 7 vulnerabilities affecting the popular DNS forwarder dnsmasq.
> These issues put networking and other devices at a risk of compromise and affect millions of Internet users which can suffer from the cache poisoning attack and RCE presented.
> This highlights the importance of DNS security in general and the security of DNS forwarders in particular.
> It also highlights the need to expedite the deployment of DNS security measures such as DNSSEC, **DNS transport security and DNS cookies**.

It sights a lack of creativity of DNS toolset mostly and these senseless users are used to pseudo newcome and speaking yogurt.  
The fact is repique never aims at being a DNS server application so that it never performs overhead design or pseudo implementation.  
However repique did most DNS stub never did, a powerful, dynamic and flexible program with interoperability to strong encryption protocols and routines to synthetic data.
# ![repique TLS1.3](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/tls_my_server_name.png?raw=true)
Illustration of sending TLS1.3 Client Hello to IBM's server by repique

# ![repique TLS1.3](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/repique_DoT_v13_cecpq2.png?raw=true)
Illustration of communication with Google's public server using DoT and [Combined Elliptic-Curve and Post-Quantum 2](https://en.wikipedia.org/wiki/CECPQ2) by repique  
It is not included in the releases, nevertheless you can find the pretty easy and straightforward implementation at my GITHUB gist.

> You may find out the difference of TLS 1.3 golang implementation inside above snapshot. It's ture.  
> Repique demonstrates the ability to mod golang std-library and build together, meanwhile it won't be shipped with the release.  
> For more information, see GITHUB gist:
> 1. [Golang - Secure Windows CryptoAPI calling when verifying certificate](https://gist.github.com/AZ-X/f2bf1e4aa6704eb168b998efcc89b9b2)
> 1. [Golang - stdlib RNG migration for Windows](https://gist.github.com/AZ-X/1dff5963486807c848eff8ef482f1425)
> 1. Others such as **bypassing** INTEL's AES-NI won't be presented on gist because it just takes 5 minutes after saw issues like [`how to disable aes-ni usage`](https://github.com/golang/go/issues/43649), thus everybody can get this done without gist.


Repique can share cache and patterns between multiple listeners or on the contrary, isolate them as independence.  
Repique can create nested groups for upstreams as well as tags for extra definition of upstreams.  
Repique can use regular expressions to dispatch queries to groups, tags and listeners.  
Repique has less explicit fingerprints and interaction behaviors than the rest of applications.  
Repique enforces TLS to fix on **version 1.3** and therefore **bypasses** https 1.1.  
Repique uses same ordered cipher suites no matter of what hardware features running on and has **discarded** `TLS_AES_128_GCM_SHA256` from v1.3 suites.  
Repique uses compatible upstreams definitions with dnscrypt-proxy and compatible routines with Acrylic DNS.  
Repique is the only alternative golang implementation conform to dnscrypt protocol.  
Repique goes beyond other stubs by implementing preload functions and various cache procedures.(See [example](https://github.com/AZ-X/pique/blob/master/examples/configuration/black_cloaking_routine.txt.example))

## Who use pique or repique

- People who take care of 'DNS Privacy'.
- People who desire an inclusive DNS stub.
- People who start prioritizing digital freedom, privacy and security across convenience and cost.
- People who accept/cognize possible sophisticated analysis on encryption protocols as well inner/outer states by public servers, non-agreement front/back-end of services and mid hops.
- People who understand the first principle of **Zero Trust**.
- People who practise **Zero Trust** security with open source contributions and vendors.
- People who have a background in computer science and normal IQ able to produce exact regular expressions for repique
- People who study golang or cryptoanalysis.
- People who can foresee the future form of IoT evolvement.

### Comparison between repique and dnscrypt-proxy

Since repique started from dnscrypt-proxy R2, introducing an overall changes to advantages is necessary to specify:  
1. Rewritten crypto functions
1. Rewritten all protocols baseline
1. Improved debug info so as to achieve principal stage of module based iteration methodology
1. Improved flows and data handling
1. Improved general design of common CLI program
1. Strict & Small & Smart

Finally, comparing both release size on Windows(with go1.15;zipped):
-      dnscrypt-proxy-win64-2.0.45.zip 2.86 MB
-      repique_windows_amd64.zip 1.85 MB  
-      repique_windows_amd64.zip 1.76 MB (golang 1.16 Feb.18)  
:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:

### Comparison between repique and nextdns

Next just compare the size of both :)
>>nextdns_1.11.0_windows_amd64.zip[(QUIC not included)](https://github.com/nextdns/nextdns/tree/v1.11.0) 2.25 MB (golang 1.15.1 Mar.9)  
repique_windows_amd64.zip 1.85 MB  
repique_windows_amd64.zip 1.76 MB (golang 1.16 Feb.18)  

:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:	:o:

### Comparison between repique and dnsmasq/pihole-FTL

Pihole-FTL is an enhanced(it's called coupling) dnsmasq copy with database, lua scripting, DHCP-discover and signals/regex support.  
Pihole-FTL is a fat variation of dnsmasq even has a set of Telnet API.  
Pihole-FTL/dnsmasq is a regular DNS server comparing to repique.  
Pihole-FTL/dnsmasq doesn't support encryption protocols.  
It is always recommended to use repique combining with a DNS server if hosting on a capable device.

### Comparison between repique and pihole-MassDNS

Repique can run on different OS while MassDNS is designed to run on Linux.

### Comparison between repique and djb'dns

Repique and djbdns share some common legends: both of them are reaction-propelled DNS project.  
Djbdns was started because of black hole inside BIND DNS.  
Repique was started because of dissentient vendoring, privacy and size of dnscrypt-proxy.  
Repique is a modern DNS stub while djbdns is an old fashion DNS server after all.

### Comparison between repique and NLnet Labs' stubby

Just like other NLnet Labs' project, stubby has external dependencies on OpenSSL, libunbound, libidn2.  
Repique has internal dependencies on Google's golang std libs.  
Repique and stubby use different cryptographic primitives.  
There is no complex routines or strict/flexible TLS when using stubby.

### Comparison between repique and CoreDNS

> CoreDNS is a DNS server that chains plugins

Repique is a DNS stub that discarded plugins  
If using CoreDNS as a forwarder, applicable size is `coredns_1.8.1_windows_amd64.tgz` 12.4 MB (extracted `coredns.exe` 41.0 MB)

### Comparison between repique and Acrylic DNS

Acrylic is a DNS stub built with Delphi 7.  
Repique is built with golang fresh version.  
Repique can build with consistency on any machine and check its fidelity.  
Acrylic supports less complex routines.

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

### Releases

Check out [Releases Page](https://github.com/AZ-X/pique/releases)

### Installation

[Download the latest release with golang 1.15 for AMD64 on Windows or Linux](https://github.com/AZ-X/pique/releases/tag/v1.2.12)

> Notice:  
> Releases for OpenWRT won't be included in this repository @github.  
> AMD64 Linux is considered an exception. 

### Usage

#### As Go Modules

Since version v1.1.5 of repique, you can use its sub-modules as libraries formally by `go get`.

However you still can get the source code and reuse it by 'git-clone' whatever the version is.

#### Practicable Build with Golang 1.18 or above

There are two options to build from the branch special for go1.18:

1. Change the source code by yourself and compile it.
1. Mod your own compiler just like what I did, then just compile the source code without modification.

There won't be any binary release targeting 1.18 because the risk of CoT (compiler of things) is extraordinary thus I am quite sluggard to alter the form of linknames.

[branch 1.18 works as below](https://github.com/AZ-X/pique/tree/repique-release-golang1.18)

![repique golang 1.18 double wing](https://raw.githubusercontent.com/AZ-X/MEDIA/master/PNG/repique_presentation/repique1.18.png)  

#### X-Copy deployment

There is no additional service or setup to run repique.

You are free to run it as service by searching existing mature methodology from the `Internet`.

#### Command Line Interface Options:

|flags|description|
|--|--|
|–check=true|check the configuration file and exit|
|-version|print current version and exit|
|–config=[path]|Path to the configuration file (default `repique.toml` in current folder when omitted or not specified)|
|–tz=[name]|name of time zone (omit it if tz file is unavailable for current OS or on Windows)|
|–tzoff=[hours]| offset(hours) of time zone e.g. -tzoff=-3, -tzoff=1 |

#### Configurations

Only three configuration files compose the configurations for a common scenario(shared routine) usage.  
1. Single `.md` file for upstreams definitions; SEE >>>>> [HOW TO](https://github.com/AZ-X/WPF-GO-dnscrypt-proxy-md/wiki)
1. Single `.toml` file for program parameters; SEE >>>>> [EXAMPLE](https://github.com/AZ-X/pique/blob/master/examples/configuration/repique.toml.example)
1. Single `any` named file for routine; SEE >>>>> [EXAMPLE](https://github.com/AZ-X/pique/blob/master/examples/configuration/black_cloaking_routine.txt.example)

`.md.minisig` is automatically generated by the great [GUI TOOL](https://github.com/AZ-X/WPF-GO-dnscrypt-proxy-md/releases/tag/latest)

# ![repique files](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/repique_folder_listview.PNG?raw=true)
Illustration of program files on Windows

## Versioning

Repique has dual version association.

Primary releases shipped with binaries are versioned like this:  
>               _______________________|--number 2 : V2 (previous R2)
>              |       ________________|--sequencing number from 1
>              |      |        ________|--X : fixed X mark
>              |      |       |
>     Ver. + MAJOR.MINOR.SUBRELEASE

Secondary tag releases with git and github are versioned like this:  
>            ________________________|--number 1 : for golang semantic versioning
>           |       _________________|--sequencing number from 1
>           |      |        _________|--counter numbers of minor update
>           |      |       |
>     v + MAJOR.MINOR.SUBRELEASE

MINOR versions of the twinned version are always matched for a single release.


## Server Name Indication :notebook_with_decorative_cover:

:ghost: rfc3546 :ghost: draft-ietf-tls-rfc4366-bis-12 :ghost: rfc6066  
```c#
'BCI/RSA Security/Transactionware/Vodafone/Stellar Switches/Huawei USA'
```

### Repique's wonderful adventure without SNI

# ![repique TLS1.3](https://github.com/AZ-X/MEDIA/blob/master/PNG/repique_presentation/DoT_no_server_name.png?raw=true)

### Repique's respecting and disrespecting low TTL

Repique respects TTL of any record from upstream resolvers or local routines, on the contrary, Repique's bats cache discards the TTL when caching.

> However, it will drastically reduce latency, and improve privacy and reliability by avoid unneeded queries.  
> Of course, RFCs say that TTLs should be stricly respected.  
> But the reality is that DNS has become quite inefficient.  

## Autobiography

[discussions...](https://github.com/AZ-X/pique/discussions/11)

:arrow_double_down::arrow_double_down::arrow_double_down: old snapshot when middle ages

# ![repique dnscrypt-proxy-r2-legacy](https://github.com/AZ-X/MEDIA/blob/master/PNG/dnscrypt-proxy-r2-mips.png?raw=true)




