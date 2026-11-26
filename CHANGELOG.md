# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 2.1.2 are described by their release commits.

## 2.2.5 - 2026-11-26

### Fixes

- Require sdk-go v5.22.1: a condition on the verdict is no plan gap for a request that sent no agent ([`365e930`](https://github.com/vpndetection-io/sdk-go-gin/commit/365e9302a5276b0f63ba3f16fba054d3c255044d))

## 2.2.4 - 2026-11-26

### Features

- Require sdk-go v5.22.0: AllowBots sends only a crawler's User-Agent, at most four an address ([`cc483ae`](https://github.com/vpndetection-io/sdk-go-gin/commit/cc483aebfe385ae5930819442b8885ecff979c3c))

## 2.2.3 - 2026-11-25

### Fixes

- Require sdk-go v5.21.1: its doc comments name a paid plan, the entitlement example the Data plan ([`a1b2bbe`](https://github.com/vpndetection-io/sdk-go-gin/commit/a1b2bbe252c321ec069b1e1832f4d6fb1b8b4b1f))

## 2.2.2 - 2026-11-24

### Fixes

- Require sdk-go v5.21.0: a condition on a list member matches any element ([`a08d780`](https://github.com/vpndetection-io/sdk-go-gin/commit/a08d7804cf34bb817edb3b9d72c7c342c533edf3))

## 2.2.1 - 2026-11-24

### Fixes

- Require sdk-go v5.20.1: a detail's first and last seen read as days ([`b90c360`](https://github.com/vpndetection-io/sdk-go-gin/commit/b90c360dac9ae7dedb7cb2215a722b7d63cc400f))

## 2.2.0 - 2026-11-23

### Features

- AllowBots: send the visitor's user agent, and let a verified crawler through ([`60ea192`](https://github.com/vpndetection-io/sdk-go-gin/commit/60ea1928ed16c9e0d2b320e0a6a20ce736101019))
- README: AllowBots, what it sends, and that a keyless client never gets a verdict ([`16cba40`](https://github.com/vpndetection-io/sdk-go-gin/commit/16cba405570554a971ebb4220c1bbd499a472621))
- Require sdk-go v5.20.0: a visitor's user agent, and AllowBots ([`53ed861`](https://github.com/vpndetection-io/sdk-go-gin/commit/53ed861b3300f79e9641ecf24be9bcfd06f1149d))

## 2.1.36 - 2026-11-22

### Features

- Require sdk-go v5.19.0: is_bot and bot, and an AS answer read whole ([`d942969`](https://github.com/vpndetection-io/sdk-go-gin/commit/d94296983c2b05e3d22a8abf77aecfe97ec74c18))

### Fixes

- Require golang.org/x/crypto v0.59.0 and golang.org/x/net v0.62.0 ([`13ed417`](https://github.com/vpndetection-io/sdk-go-gin/commit/13ed417ad83667722178d19a6a40e6d15d7f1e2c))

## 2.1.35 - 2026-11-20

### Fixes

- Require sdk-go v5.18.0: the network, service, company and abuse members ([`bff6cc9`](https://github.com/vpndetection-io/sdk-go-gin/commit/bff6cc92bf409b2578ccbd0f4a532c70902c442c))

## 2.1.34 - 2026-11-19

### Fixes

- Require sdk-go v5.17.1: re-pinned to spec 2026.11.18 ([`f64e8ea`](https://github.com/vpndetection-io/sdk-go-gin/commit/f64e8ea09b8b62339e6d029314d559ca151b9d20))

## 2.1.33 - 2026-11-18

### Fixes

- Require sdk-go v5.17.0: cap_reached past a paid plan's overage cap ([`fdf6f0a`](https://github.com/vpndetection-io/sdk-go-gin/commit/fdf6f0a138b26e4919a7444d546083d6c5719362))

## 2.1.32 - 2026-11-16

### Fixes

- Require sdk-go v5.16.0: the plan's name ([`401d2ca`](https://github.com/vpndetection-io/sdk-go-gin/commit/401d2ca6ef10c584236d68894867bbef815c4c02))

## 2.1.31 - 2026-11-14

### Fixes

- Require vpndetection v5.15.0: is_bogon on every answer, and provider_name beside each provider ([`05b44c2`](https://github.com/vpndetection-io/sdk-go-gin/commit/05b44c2a0ff5b260330e00073e47128998a4c7c7))

## 2.1.30 - 2026-11-13

### Fixes

- Require vpndetection v5.14.0: every request names the SDK in its User-Agent ([`f13c298`](https://github.com/vpndetection-io/sdk-go-gin/commit/f13c29867fad54bd890f3b99f1064a0dd6dea52e))

## 2.1.29 - 2026-11-11

### Fixes

- Require vpndetection v5.13.2: Unlimited, the free plan, never the Unlimited tier ([`8083518`](https://github.com/vpndetection-io/sdk-go-gin/commit/80835188cbc7f0e9f6ccb719963286f7ee808aaa))

## 2.1.28 - 2026-11-11

### Fixes

- Require vpndetection v5.13.1: the free plan's daily trial, never a trial key ([`a2ed89f`](https://github.com/vpndetection-io/sdk-go-gin/commit/a2ed89f88378b7c7850cc4cc4c90bca5f1b9da40))

## 2.1.27 - 2026-11-11

### Features

- Require vpndetection v5.13.0: trial_expired on a trial key's answers ([`2e1d47c`](https://github.com/vpndetection-io/sdk-go-gin/commit/2e1d47c9ef0e148b1e72344dfa97b59a2de7476b))

## 2.1.26 - 2026-11-11

### Fixes

- Require vpndetection v5.12.2: the Unlimited tier and its terms ([`2a01318`](https://github.com/vpndetection-io/sdk-go-gin/commit/2a01318ef84f19359db9a456c7120cad39681014))

## 2.1.25 - 2026-11-11

### Fixes

- Require vpndetection v5.12.1: plainer words on lookups without a key ([`6d4785e`](https://github.com/vpndetection-io/sdk-go-gin/commit/6d4785e264c1fd41411b43b69717d1b83f596fff))

## 2.1.24 - 2026-11-11

### Features

- Require vpndetection v5.12.0: a lookup without a key answers more ([`334c51f`](https://github.com/vpndetection-io/sdk-go-gin/commit/334c51f09afe6cf20b665d3b682657f51385c2b5))

## 2.1.23 - 2026-11-08

### Fixes

- Require sdk-go v5.11.1: the download methods keep v5.10's signatures ([`0632452`](https://github.com/vpndetection-io/sdk-go-gin/commit/0632452e6dc45657dbdc49ff88582484e8c0d245))

## 2.1.22 - 2026-11-07

### Features

- Require sdk-go v5.11.0: downloads take the build a webhook names ([`e053498`](https://github.com/vpndetection-io/sdk-go-gin/commit/e0534986eebe506fdd32fcae8cdc418e4c6d8876))

## 2.1.21 - 2026-10-29

### Fixes

- Require sdk-go v5.10.2: a lowercase t or z read, negative per-call retries refused ([`6640d57`](https://github.com/vpndetection-io/sdk-go-gin/commit/6640d57014fe275b2cf5cd6eeba6caa4ec034394))

## 2.1.20 - 2026-10-26

### Fixes

- Require sdk-go v5.10.1: re-pinned to the 2026.10.25 spec ([`12eec97`](https://github.com/vpndetection-io/sdk-go-gin/commit/12eec975ec052c3152c13a9b8c28531d38c61086))

## 2.1.19 - 2026-10-22

### Fixes

- Require sdk-go v5.10.0: Retry-After and date-time zones, Oauth.Register ([`193d6fd`](https://github.com/vpndetection-io/sdk-go-gin/commit/193d6fde7d06072bd40c0d224dc9f23017629d29))

## 2.1.18 - 2026-10-20

### Features

- Require sdk-go v5.9.0: lookup results carry Location and Asn ([`077807c`](https://github.com/vpndetection-io/sdk-go-gin/commit/077807cb615f44bedbdd399dd914cce736c9784c))

## 2.1.17 - 2026-10-19

### Fixes

- Require sdk-go v5.8.0: num_ports and num_proxies in the pubproxy detail ([`35420d1`](https://github.com/vpndetection-io/sdk-go-gin/commit/35420d1838bef29064cd10a838f3c572df05c544))

## 2.1.16 - 2026-10-18

### Fixes

- Require sdk-go v5.7.0: is_pubproxy and the pubproxy detail ([`a6d227f`](https://github.com/vpndetection-io/sdk-go-gin/commit/a6d227f106c2b8d3275d1f8a8cc62d246de0134e))

## 2.1.15 - 2026-10-17

### Features

- Require sdk-go v5.6.0: OauthMetadata carries registration_endpoint ([`3727346`](https://github.com/vpndetection-io/sdk-go-gin/commit/3727346b15d21665a9d54050003b4706af9068a1))

## 2.1.14 - 2026-10-16

### Fixes

- Require sdk-go v5.5.3: unreadable answers retried, the key trimmed ([`dc54c0d`](https://github.com/vpndetection-io/sdk-go-gin/commit/dc54c0d4d0307b5591a13365e5acf981d9133b79))

## 2.1.13 - 2026-10-10

### Fixes

- Require sdk-go v5.5.2: the spec re-pinned to 2026.10.09 ([`64784bd`](https://github.com/vpndetection-io/sdk-go-gin/commit/64784bd1b70b0e9f1accfc70b5d8b7d09dde55ea))

## 2.1.12 - 2026-10-10

### Fixes

- Require sdk-go v5.5.1: the middleware starts with only an API key ([`960d287`](https://github.com/vpndetection-io/sdk-go-gin/commit/960d287ae5d2d21ece0026674093380a2253d93e))

## 2.1.11 - 2026-10-09

### Fixes

- Require golang.org/x/net v0.60.0: four HTTP/2 server fixes ([`970e4a4`](https://github.com/vpndetection-io/sdk-go-gin/commit/970e4a4e1935f85ff9b74c374cd0ab0739d32da4))

## 2.1.10 - 2026-10-04

### Features

- Require sdk-go v5.5.0: the authorization code sign-in ([`9e38ed2`](https://github.com/vpndetection-io/sdk-go-gin/commit/9e38ed2f0ce4819c8b3c52868cf0ca3f21cf6b00))

## 2.1.9 - 2026-10-04

### Fixes

- Require sdk-go v5.4.4, re-pinned to spec 2026.10.03 ([`4bacdf6`](https://github.com/vpndetection-io/sdk-go-gin/commit/4bacdf689724629cae0884b6b7f22966be70351a))

## 2.1.8 - 2026-09-29

### Fixes

- Require sdk-go v5.4.3: 26 more reserved ranges are answered locally ([`d40da7f`](https://github.com/vpndetection-io/sdk-go-gin/commit/d40da7ff30a656960e5e00c80ae1f1b08911e819))

## 2.1.7 - 2026-09-28

### Fixes

- Require sdk-go v5.4.2: IPv4-mapped visitors are looked up, not waved through ([`dc1465e`](https://github.com/vpndetection-io/sdk-go-gin/commit/dc1465ee6075e5e25b4b1959fc3cf41f6cd70e1d))

## 2.1.6 - 2026-09-28

### Fixes

- Require sdk-go v5.4.1: builds on 32-bit platforms again ([`e4afb52`](https://github.com/vpndetection-io/sdk-go-gin/commit/e4afb52a01299bacc28bee7d541ba5830fbdbd86))

## 2.1.5 - 2026-09-27

### Features

- Require sdk-go v5.4.0: OauthMetadata carries client_id_metadata_document_supported ([`7baa4aa`](https://github.com/vpndetection-io/sdk-go-gin/commit/7baa4aadf3bd3e914edcbec95b53ad994f10d5eb))

## 2.1.4 - 2026-09-27

### Fixes

- Require sdk-go v5.3.4: bounded Retry-After and poll, no doubled slash ([`6f71c56`](https://github.com/vpndetection-io/sdk-go-gin/commit/6f71c564fe1e3891083a0e7a144e884c9e312071))

## 2.1.3 - 2026-09-26

### Fixes

- Require sdk-go v5.3.3: DownloadBytes no longer panics ([`efaf0a2`](https://github.com/vpndetection-io/sdk-go-gin/commit/efaf0a2f72967016cfa093d1fd574786df7f5c44))

## 2.1.2 - 2026-09-25

### Fixes

- Require sdk-go v5.3.2 ([`2f96bf6`](https://github.com/vpndetection-io/sdk-go-gin/commit/2f96bf6a96a1b23f0d7b1d7db59bc027601ab56b))
