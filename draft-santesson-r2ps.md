---
title: "Remote Two-factor Protected Services"
abbrev: "R2PS"
ipr: "trust200902"
category: std

docname: draft-santesson-r2ps-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
date: 2026-06-15
consensus: true
v: 3
# area: Security
keyword:
- remote
- HSM
- opaque
- services
venue:
  github: "Razumain/r2ps-ietf-draft"

author:
-
  ins: S. Santesson
  name: Stefan Santesson
  org: IDsec Solutions AB
  abbrev: IDsec Solutions
  street: Forskningsbyn Ideon
  city: Lund
  code: "223 70"
  country: SE
  email: sts@aaa-sec.com
-
  ins: P. Altmann
  name: Peter Altmann
  org: SIROS Foundation
  abbrev: SIROS
  city: Stockholm
  country: SE
  email: peter.altman@siros.se

normative:
  RFC4648:
  RFC5869:
  RFC7515:
  RFC7516:
  RFC7518:
  RFC7638:
  RFC9807:

informative:

--- abstract

This document defines a generic service exchange protocol where service exchange data is protected and bound to a physical user using 1 or 2 factors (1FA and 2FA). The protocol facilitates registration and verification of either a knowledge-factor or a biometric factor in addition to a possession factor as means of achieving 2 factor protection.

--- middle

# Introduction

Password-Authenticated Key Exchange (PAKE) protocols let two parties derive a shared key from a low-entropy password without disclosing it, while resisting offline guessing. An augmented PAKE (aPAKE) further protects against server compromise.

This document complements the capabilities of PAKE protocols by defining a service exchange protocol that can be used to:

- exchange data for a selected PAKE protocol, or any other protocol that validates a user knowledge or biometric factor, to establish a shared session key; and
- exchange service data protected under that session key.

This document uses the OPAQUE aPAKE [RFC9807] as its RECOMMENDED mechanism for verifying a knowledge factor without exposing it to the server.

## Applicability for EU trust frameworks

EU has defined a level of assurance framework for user authentication based on an eID [1502]. On the highest assurance level (LoA High) the key used to authenticate the user must be protected by tamper resistant hardware (HSM) that protects against an adversary with high attack potential. This framework further specifies that access to the protected authentication key must be protected by 2-factor authentication.

The EU Digital Identity Wallet (EUDI Wallet) defined by the new eIDAS regulation [{add ref}] specifies that HSM protection when the wallet provides authentication on LoA High, must be realized by a Wallet Secure Cryptographic Application (WSCA) that includes a Wallet Secure Cryptographic Device (WSCD).

The WSCA is a software module responsible for controlling access to keys protected by the hardware module (WSCD).

Some wallet actions, such as presenting a Verifiable Presentation on LoA High, requires the user to provide a knowledge-factor or a biometric factor together with a possession factor to access necessary keys. This action may require one or more service request to a backend service such as the WSCA.

This protocol is designed as a framework for such service exchanges based on two-factor user authentication that allows the client and server to use any suitable mechanism for user authentication.



# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Definitions

The following terms have a defined meaning in this document:

- context: A security scope, cryptographically separated from other contexts by a unique set of context keys held at the client and the server. The client-side context keys also represent the user's possession factor in two-factor protection modes.
- context key: A public/private key pair. Each context is bound to one context key-agreement key and one context signing key, at both the server and the client.
- protection mode: This document defines two protection modes, one-factor protection (1FA) and two-factor protection (2FA). 1FA provides protection based on one user factor (the possession factor); 2FA provides protection based on two user factors (the possession factor together with a knowledge or biometric factor).
- session: A scope bound to a session key derived from two-factor authentication of the user, which requires the user to be present to provide a knowledge or biometric factor. A session MAY be bound to a specific task.
- service type: A defined message type, with its own data structure, that can be exchanged using R2PS.
- task: Defines what a session is to achieve before it is terminated. A task MAY be negotiated when creating a session and lets the client and the server terminate the session as soon as the task completes or fails, even before the session timeout is reached.
- first factor: The user's possession factor, which corresponds to a set of client context keys.
- second factor: The user's knowledge factor or biometric factor.

# Basic structure

R2PS is a stateless request/response protocol. Each request and each response is carried as a JSON Web Encryption (JWE) object [RFC7516] in compact serialization, providing end-to-end encryption between the client and the backend server that provides the service. The JWE payload is a JSON Web Signature (JWS) object [RFC7515] in compact serialization, signed by the sender, that carries a request or response structure common to all exchanges together with service data identified by a service type.

The backend server determines the protection mode from the JWE protected header. R2PS defines two protection modes: `1FA`, authenticated by a possession factor (the device key); and `2FA`, authenticated additionally by the user's second factor. The service type identifier carried in the inner JWS determines the structure of the service data, the operations performed, and the required protection mode.

~~~ ascii-art
+-----------------------------------------------------------------+
| JWE  (compact serialization)                                    |
|   protected header: typ (r2ps-1fa | r2ps-2fa), alg, enc         |
|                                                                 |
| +-----------------------------------------------------------+   |
| | JWS  (compact serialization)                              |   |
| |   protected header:                                       |   |
| |     typ (r2ps-request+jwt | r2ps-response+jwt),           |   |
| |     alg=ES256, kid                                        |   |
| |                                                           |   |
| |   payload:                                                |   |
| |     ver, nonce, iat       (common to all exchanges)       |   |
| |     type, jwe_hash        (requests only)                 |   |
| |     data { service-specific request or response }         |   |
| +-----------------------------------------------------------+   |
+-----------------------------------------------------------------+
~~~
{: title="R2PS outer JWE and inner JWS structure"}

The protocol allows the client and server to agree on any number of service type identifiers, each having its own defined data structure for request and response data.

While the base protocol structure has no state, the inner service data structure may be used in a process that requires state. This is defined by each service type.

This specification defines a set of default service types. Other service types MAY be defined by other documents.

## Bootstrapping the protocol

The protocol is designed to serve the need for service exchange with many different server resources, each cryptographically separated from the others.

This is achieved by means of separate "context keys" at the client and server. A security context is a named scope identified by a context id, under which a set of service types is offered with a common security and key-management policy. Each security context has its own context key set (a signing key and a key-agreement key) and is cryptographically separated from all other security contexts.

The manner through which the client and server share trusted context keys is out of scope of this specification.

Initial registration of a user's 2nd factor may need authorization data that was provided to the user by out-of-band means. This MAY be a one-time password or other authorization data that asserts that the user factor is provided by the intended user. The protocol facilitates exchange of such authorization data in the registration process, but the composition of this data and the means for providing this data to the user is out of scope for this specification.

## Protection modes and sessions

The main purpose of this protocol is to exchange service data that is protected and authenticated under two user factors: a possession factor (the device key) and a user-bound factor (knowledge or biometric). Establishing the user-bound factor must complete before a two-factor protected exchange can take place, so the protocol also provides a one-factor protection mode, protected by the possession factor alone.

The one-factor protection mode MAY be used:

- to register or verify a user's knowledge or biometric factor; and
- for exchanges with lower protection requirements that are permitted without the user presenting a second factor.

The two-factor protection mode is used within a session bound to the user having presented a second factor, as typically required when the user signs a transaction or presents an identity. A session MAY be bound to a `task`, which in turn MAY bind to a sequence of service exchanges, each identified by a service type. This session lets both client and server track the task's progress within the session and terminate the session as soon as the task completes or the session times out.


# R2PS Protocol Components

## Outer JWE object

The outer JWE object [RFC7516] provides end-to-end encryption of the exchanged service data. It is used in one of two protection modes:

- `1FA`, where the Content Encryption Key (CEK) is derived from a static recipient key and an ephemeral sender key.
- `2FA`, where the session key derived from authentication of the user's two factors is used directly as the CEK. This mode provides forward secrecy.

The recipient determines the mode from the `typ` parameter of the JWE protected header. The JWE protected header is the only header used; per-recipient and unprotected headers are not used.

This document defines the following `typ` parameters:

- `r2ps-1fa` : identifies the 1FA mode defined in this document.
- `r2ps-2fa` : identifies the 2FA mode defined in this document.

Deployments MAY define and agree on alternative protection modes identified by other `typ` parameter values.

### 1FA mode

In `1FA` mode the CEK is derived using ECDH-ES [RFC7518]. The JWE protected header MUST contain:

- `typ`: MUST be `r2ps-1fa`.
- `alg`: MUST be `ECDH-ES`.
- `enc`: MUST be `A256GCM`.
- `epk`: the sender's ephemeral public key.
- `kid`: identifies the recipient's static key-agreement key: the server's static ECDH key in a request, the client's agreement key (CAK) in a response.
- `apu`: MUST be the `client_id` in a request and the `context` in a response.
- `apv`: MUST be the `context` in a request and the `client_id` in a response.
- `cty`: MUST be `JWT`.

where `context` identifies the security context and `client_id` is the client's identifier within that context.

The resulting compact serialization is `<header>..<iv>.<ciphertext>.<tag>`; the encrypted-key field is empty, as ECDH-ES uses direct key agreement. The sender MUST destroy the ephemeral private key and the CEK as soon as the JWE has been constructed.

### 2FA mode

In `2FA` mode the session key, derived from authentication of the user's two factors, is used directly as the CEK (`dir`, direct encryption). The JWE protected header MUST contain:

- `typ`: MUST be `r2ps-2fa`.
- `alg`: MUST be `dir`.
- `enc`: MUST be `A256GCM`.
- `kid`: the `2FA` session identifier.
- `cty`: MUST be `JWT`.

The IV MUST be a freshly generated 96-bit random value for each message. The resulting compact serialization is `<header>..<iv>.<ciphertext>.<tag>`; the encrypted-key field is empty, as direct encryption uses the session key as the CEK.

The `2FA` session identifier identifies the `2FA` session key that is negotiated during authentication of the users 2 factors. The `2FA` session key is ephemeral and MUST be destroyed after use to preserve forward secrecy.


## Inner JWS object

The inner JWS object [RFC7515] is signed by the sender with its context signing key and carries the request or response structure common to all service types. Variant content specific to a service type resides entirely within the `data` member of the payload.

The JWS protected header MUST contain at least:

- `alg`: MUST be `ES256`.
- `kid`: identifies the signing key. In a request it MUST identify the client's Client Signing Key (CSK) for the security context; implementations SHOULD use the JWK Thumbprint [RFC7638] of the CSK public key. In a response it MUST identify the server's Server Signing Key (SSK).
- `typ`: MUST be `r2ps-request+jwt` in a request and `r2ps-response+jwt` in a response.

The JWS payload is a JSON object. Members that hold a binary value are encoded as base64 strings as defined in [RFC4648], Section 4 (the standard base64 alphabet, with padding). The following members are common to all exchanges and MUST be present in both requests and responses:

- `ver` (string): the protocol version; `"1.0"` for this document.
- `nonce` (string): a base64-encoded random byte array carrying at least 16 bytes of entropy. The client generates it for each request, and the server echoes it unchanged in the corresponding response.
- `iat` (integer): the message creation time as a Unix timestamp. The server MUST enforce a maximum `iat` age and MUST reject a duplicate `nonce` received within that window. Freshness windows and the state required for replay protection are deployment-defined.
- `data` (object): the service-specific payload, whose structure is determined by the service type.

### Request data

In addition to the common members, a request payload MUST include the following, which MUST NOT appear in a response:

- `type` (string): the service type identifier. It determines the structure of `data`, the operations performed, and the required protection mode (`1FA` or `2FA`).
- `jwe_hash` (string): a digest binding this JWS to the JWE that encrypts it, constructed as defined below.

The `jwe_hash` binds the signed payload to the JWE protected header that carries it, preventing surreptitious forwarding (a recipient re-encrypting the inner JWS under a different JWE). It is computed over the JWE Protected Header exactly as transmitted in compact serialization. This is defined in JWE [RFC7516] as BASE64URL(UTF8(JWE Protected Header)), which is the octets preceding the first period in compact serialization. The sender computes the SHA-256 digest of the ASCII octets of that encoded header and carries the resulting 32-octet digest in the `jwe_hash` member, encoded as a base64 string.

~~~ ascii-art
jwe_hash = SHA-256( ASCII( BASE64URL(UTF8(JWE Protected Header)) ) )
~~~

The recipient MUST recompute `jwe_hash` over the received encoded JWE Protected Header and MUST reject the message on mismatch.

### Response data

A response payload carries the common members only; it MUST NOT include `type` or `jwe_hash`. The `nonce` MUST equal the `nonce` of the request being answered. The response `data` object carries the service-specific response defined by the service type, typically a mechanism-specific `response` element and an optional human-readable `message`.

## Two-factor authentication and session key derivation

This section defines common service types for registration, update and authentication of a user's second factor.

These service type exchanges are also bound to the user's first factor by either using 1FA or 2FA protection mode as defined by each service type.

The output of authentication of the user's second factor is:

- session key: a key suitable for direct use as the CEK in the 2FA protection mode in use; its length and parameters are determined by that mode's encryption algorithm. This key MUST be uniformly distributed, MUST be unique per session, and MUST provide forward secrecy.
- session identifier: an identifier of the session key and the properties bound to it.
- context: the context under which the session is exchanged.
- task: an optional identifier of the task to be performed within the session.

A second-factor authentication mechanism that already outputs a key meeting these requirements (for example, the session key produced by OPAQUE [RFC9807]) MAY use that key directly as the session key. Otherwise, the mechanism MUST derive a suitable key from its output, for example using HKDF [RFC5869].

### Service types

TBD - This section will define one service type of session creation based on authentication of 2nd factor, and a service type for registering the 2nd factor

### Defined authentication protocols

#### OPAQUE

TBD - Specify how to use OPAQUE

#### Fido

TBD - Specify use of Fido


# Security Considerations

Security considerations goes here

Note: Implementers MUST provide a new random IV for every JWE

# IANA Considerations

IANA considerations goes here


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
