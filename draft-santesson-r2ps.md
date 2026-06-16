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
  ins: P. Altman
  name: Peter Altman
  org: SIROS Foundation
  abbrev: SIROS
  city: Stockholm
  country: SE
  email: peter.altman@siros.se

normative:
  RFC2119:
  RFC8174:
  RFC5869:
  RFC7515:
  RFC7516:
  RFC7518:
  RFC7638:
  RFC9807:

informative:

--- abstract

This document defines a generic service exchange protocol where service exchange data is protected and bound to a physical user using 1 or 2 factors (1FA and 2FA). The protocol facilitates registration and verification of either a knowledge-factor or a biometric factor under 1 factor protection as means of achieving 2 factor protection.

--- middle

# Introduction

Several protocols are capable of authentication and key exchange based on a password.

A Password-Authenticated Key Exchange (PAKE) lets two parties derive a shared key from a low-entropy password without disclosing it, while resisting offline guessing. An augmented PAKE (aPAKE) further protects against server compromise: the server stores only a password-derived verifier, never the password itself, so a stolen verifier yields at most an offline attack and cannot be replayed against the protocol. This document uses the OPAQUE aPAKE [RFC9807] as its RECOMMENDED mechanism for verifying a knowledge factor without exposing it to the server.

EU has defined a level of assurance framework for user authentication based on en eID [1502]. On the highest assurancelevel (LoA High) the key used to authenticate the user must be protected by tamper resistant hardware (HSM) that protects against an adversary with high attack potential. This framework further specifies that access to the protected authentication key must be protected by 2-factor authentication.

The EU Digital Identity Wallet (EUDI Wallet) defined by the new eIDAS regulation [{add ref}] specifies that HSM protection when the wallet provides authentication on LoA High, must be realized by a Wallet Secure Cryptographic Application (WSCA) that includes a Wallet Secure Cryptographic Device (WSCD).

The WSCA is a software module responsible for controlling access to keys protected by the hardware module (WSCD).

Some wallet actions, such as presenting a Verifiable Presentation on LoA High, requires the user to provide a knowledge-factor or a biometric factor together with a possession factor to access necessary keys. This action may require one or more service request to a backend service such as the WSCA.

This protocol is designed as a framework for such service exchanges based on two-factor user authentication that allows the client and server to use any suitable mechanism for user authentication.

For this reason this protocol defines to protection profiles (1FA and 2FA). The 1FA mode allows device authenticated exchange before the user 2nd factor has been validated, and the 2FA mode provides user authenticated exchange based on a session key derived from authentication of the 2nd factor.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Basic structure

R2PS is a stateless request/response protocol. Each request and each response is carried as a JSON Web Encryption (JWE) object [RFC7516] in compact serialization, providing end-to-end encryption between the client and the backend server that provides the service. The JWE payload is a JSON Web Signature (JWS) object [RFC7515] in compact serialization, signed by the sender, that carries a request or response structure common to all exchanges together with service data identified by a service type. A service type MAY define a different JWE payload, but a payload that carries no signed `nonce` and `iat` provides no freshness guarantee and is NOT RECOMMENDED.

The backend server determines the encryption mode from the JWE header. R2PS defines two modes: `1FA`, where the exchange is protected under a key derived from a static recipient key and an ephemeral sender key, proving a possession factor; and `2FA`, where the exchange is protected under a session key negotiated from verification of the user's second factor. The service type identifier carried in the inner JWS determines the structure of the service data, the operations performed, and the required mode.

~~~ ascii-art
+===============================================================+
|  JWE  (compact serialization)                                 |
|  protected header: alg, enc, key-management mode (1FA | 2FA)  |
|                                                               |
|  +---------------------------------------------------------+  |
|  |  JWS  (compact serialization)                           |  |
|  |  protected header: typ=r2ps-2fa alg=ES256, kid        |  |
|  |                                                         |  |
|  |  payload:                                               |  |
|  |    ver, nonce, iat        (common to all exchanges)     |  |
|  |    type, jwe_hash         (requests only)               |  |
|  |    data { service-type-specific request or response }   |  |
|  +---------------------------------------------------------+  |
+===============================================================+
~~~
{: title="R2PS outer JWE and inner JWS structure"}

The protocol allows the client and server to agree on any number of service type identifiers, each having its own defined data structure for request and response data.

While the base protocol structure has no state, the inner service data structure may be used in a process that requires state. This is defined by each service type.

This specification defines default service types for negotiation and verification of the user's 2nd factor.
Other service types MAY be defined by other documents.

## Bootstrapping the protocol

The protocol is designed to serve the need for service exchange with many different server resources, each cryptographically separated from the others.

This is achieved by means of separate "context keys" at the client and server. A security context is a named scope identified by a context id, under which a set of service types is offered with a common security and key-management policy. Each security context has its own context key set (a signing key and a key-agreement key) and is cryptographically separated from all other security contexts.

The manner through which the client and server share trusted context keys is out of scope of this specification.

Initial registration of a user's 2nd factor may need authorization data that was provided to the user by out-of-band means. This MAY be a one-time password or other authorization data that asserts that the user factor is provided by the intended user. The protocol facilitates exchange of such authorization data in the registration process, but the composition of this data and the means for providing this data to the user is out of scope for this specification.

# R2PS Protocol

## Outer JWE object

The outer JWE object [RFC7516] provides end-to-end encryption of the exchanged service data. It is used in one of two encryption modes:

- `1FA`, where the Content Encryption Key (CEK) is derived from a static recipient key and an ephemeral sender key.
- `2FA`, where the CEK is protected under a session key negotiated from verification of the user's two factors.

The recipient determines the mode from the `typ` parameter of the JWE protected header. The JWE protected header is the only header used; per-recipient and unprotected headers are not used.

This document defines the following `typ` parameters:

- `r2ps-1fa` : identifies the 1FA mode defined in this document.
- `r2ps-2fa` : identifies the 2FA mode defined in this document.

Deployments MAY define and agree on alternative encryption modes identified by other `typ` parameter values.

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

where `context` identifies the security context and `client_id` is the client's identifier within that context. How the client obtains the server's static ECDH public key and its `kid` is out of scope.

The resulting compact serialization is `<header>..<iv>.<ciphertext>.<tag>`; the encrypted-key field is empty, as ECDH-ES uses direct key agreement. The sender MUST destroy the ephemeral private key and the CEK as soon as the JWE has been constructed.

### 2FA mode

In `2FA` mode a fresh random CEK MUST be generated for each message and wrapped under a key-encryption key (KEK) derived from the negotiated `2FA` session key. The JWE protected header MUST contain:

- `typ`: MUST be `r2ps-2fa`.
- `alg`: MUST be `A256KW`.
- `enc`: MUST be `A256GCM`.
- `kid`: the `2FA` session identifier.
- `cty`: set according to the payload. For the inner JWS payload defined in this document it MUST be `JWT`; for a bare JWS it is `jose`, for JSON `json`, and for an arbitrary octet sequence `octet-stream`.

The IV MUST be a freshly generated 96-bit random value for each message. The resulting compact serialization is `<header>.<encrypted-key>.<iv>.<ciphertext>.<tag>`.

The `2FA` session identifier identifies the `2FA` session key that is negotiated during authentication of the users 2 factors. The `2FA` session key is ephemeral and MUST be destroyed after use to preserve forward secrecy.

The KEK is derived from the `2FA` session key using HKDF [RFC5869] as follows:

- Hash function: SHA-256.
- Input keying material (IKM): the `2FA` session key.
- Salt: the message `nonce` of the last round trip that established the session.
- Output length L: 32 bytes.
- `info`: the concatenation of the fields below, each prefixed by its length as a 4-byte big-endian unsigned integer:
  - `dst`: the ASCII bytes of `R2PS-2FA-KEK-1.0`.
  - `direction`: the 3-byte ASCII string `c2s` for client-to-server messages, `s2c` for server-to-client messages.
  - `session_id`: the `2FA` session identifier.


## Inner JWS object

The inner JWS object [RFC7515] is signed by the sender with its context signing key and carries the request or response structure common to all service types. Variant content specific to a service type resides entirely within the `data` member of the payload.

The JWS protected header MUST contain at least:

- `alg`: MUST be `ES256`.
- `kid`: identifies the signing key. In a request it MUST identify the client's Client Signing Key (CSK) for the security context; implementations SHOULD use the JWK Thumbprint [RFC7638] of the CSK public key. In a response it MUST identify the server's Server Signing Key (SSK).
- `typ`: MUST be `r2ps-request+jwt` in a request and `r2ps-response+jwt` in a response.

The JWS payload is a JSON object. The following members are common to all exchanges and MUST be present in both requests and responses:

- `ver` (string): the protocol version; `"1.0"` for this document.
- `nonce` (string): a base64url-encoded random byte array carrying at least 16 bytes of entropy. The client generates it for each request, and the server echoes it unchanged in the corresponding response.
- `iat` (integer): the message creation time as a Unix timestamp. The server MUST enforce a maximum `iat` age and MUST reject a duplicate `nonce` received within that window. Freshness windows and the state required for replay protection are deployment-defined.
- `data` (object): the service-specific payload, whose structure is determined by the service type.

Conditional members:

`2fa_session_id`: The ID of the session equal to the kid in the JWE header in 2FA mode. This member MUST be present when 2FA mode is used and MUST NOT be pressent when 1FA mode is used.

Note: The `2fa_session_id` binds the JWS to the session also when processed outside the context of the JWE. The recipient MUST verify that the value matches the kid used in the JWE header and reject the message on mismatch.

Editors remark (remove later): This is redundant to jwe_hash. Should we remove?

### Request data

In addition to the common members, a request payload MUST include the following, which MUST NOT appear in a response:

- `type` (string): the service type identifier. It determines the structure of `data`, the operations performed, and the required encryption mode (`1FA` or `2FA`).
- `jwe_hash` (string): the SHA-256 digest of the base64url-encoded JWE protected header.

To bind the signed payload to the JWE that encrypts it, and so prevent surreptitious forwarding (a recipient re-encrypting the inner JWS under a different JWE), the request payload carries the `jwe_hash` member defined below: the SHA-256 digest of the JWE protected header computed over the transmitted base64url octets. The recipient MUST recompute the digest and reject the message on mismatch.


### Response data

A response payload carries the common members only; it MUST NOT include `type` or `jwe_hash`. The `nonce` MUST equal the `nonce` of the request being answered. The response `data` object carries the service-specific response defined by the service type, typically a mechanism-specific `response` element and an optional human-readable `message`.

# Security Considerations

Security considerations goes here

# IANA Considerations

IANA considerations goes here


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
