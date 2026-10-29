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
  email: peter.altmann@siros.se

normative:
  RFC4648:
  RFC5869:
  RFC7515:
  RFC7516:
  RFC7518:
  RFC7638:
  RFC9807:
  RFC9457:

informative:
  RFC6838:
  RFC7800:
  RFC8126:
  RFC8747:
  RFC9334:
  RFC9711:

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
| |     typ (r2ps-request+jws | r2ps-response+jws),           |   |
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
- `cty`: MUST be `jose`.

where `context` identifies the security context and `client_id` is the client's identifier within that context.

The resulting compact serialization is `<header>..<iv>.<ciphertext>.<tag>`; the encrypted-key field is empty, as ECDH-ES uses direct key agreement. The sender MUST destroy the ephemeral private key and the CEK as soon as the JWE has been constructed.

### 2FA mode

In `2FA` mode the session key, derived from authentication of the user's two factors, is used directly as the CEK (`dir`, direct encryption). The JWE protected header MUST contain:

- `typ`: MUST be `r2ps-2fa`.
- `alg`: MUST be `dir`.
- `enc`: MUST be `A256GCM`.
- `kid`: the `2FA` session identifier.
- `cty`: MUST be `jose`.

The IV MUST be a freshly generated 96-bit random value for each message. The resulting compact serialization is `<header>..<iv>.<ciphertext>.<tag>`; the encrypted-key field is empty, as direct encryption uses the session key as the CEK.

The `2FA` session identifier identifies the `2FA` session key that is negotiated during authentication of the users 2 factors. The `2FA` session key is ephemeral and MUST be destroyed after use to preserve forward secrecy.


## Inner JWS object

The inner JWS object [RFC7515] is signed by the sender with its context signing key and carries the request or response structure common to all service types. Variant content specific to a service type resides entirely within the `data` member of the payload.

The JWS protected header MUST contain at least:

- `alg`: SHOULD be `ES256`.
- `kid`: identifies the signing key. In a request it MUST identify the client's Client Signing Key (CSK) for the security context; implementations SHOULD use the JWK Thumbprint [RFC7638] of the CSK public key. In a response it MUST identify the server's Server Signing Key (SSK).
- `typ`: MUST be `r2ps-request+jws` in a request and `r2ps-response+jws` in a response.

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

A request MAY also carry compliance information, using the optional members below. These are carried only in requests and are not present in responses.

- `compliance_token` (string): a compliance token demonstrating that the client meets a set of predefined policy requirements. The policy, and what the token's underlying test verifies, are out of scope of this specification.
- `compliance_proof` (string): included only together with a `compliance_token`. It carries information establishing that the presented token is rightfully held by the client presenting it. It is relevant only when the token does not already provide this function.
- `compliance_token_type` (string): included only together with a `compliance_token`. When present, it defines the type of the token and of any present proof, their format, and, where relevant, their encoding. When absent, an established default configuration is assumed. This document defines no `compliance_token_type` values. It is up to the client and the server to agree on suitable profiles and their type identifier values.

A `compliance_token` SHOULD be bound to the client presenting it, so that a token captured in transit cannot be used by another party. It may be bound to a key whose possession the client demonstrates on each presentation, or to an identity that the request itself proves through its signature.

See {{compliance-rats}} for how these members relate to attestation and the RATS architecture.

### Response data

#### Success Response

This response SHOULD be used on successful service completion, or where error handling is provided as part of service data in the response.

The response payload includes the common members only (`ver`, `nonce`, `iat` and  `data`). The `nonce` MUST equal the `nonce` of the request being answered. The response `data` object carries the service-specific response members defined by the service type, for example the `p_data` parameter.

#### Error response

If a server fails to process a request and return a normal response, e.g. due to a missing or invalid parameter, decryption error or signature validation error, etc, it SHOULD return a suitable error response.

When a HTTP API is used for service exchange, the server SHALL provide problem details as defined in [RFC9457].

The following response codes are RECOMMENDED for use in a HTTP API:

| Response code            | HTTP response code |
|--------------------------|--------------------|
| ILLEGAL_REQUEST_DATA     | 400                |
| UNAUTHORIZED             | 401                |
| ACCESS_DENIED            | 403                |
| ILLEGAL_STATE            | 409                |
| UNSUPPORTED_REQUEST_TYPE | 415                |
| SERVER_ERROR             | 500                |
| TRY_LATER                | 503                |


## Second factor establishment and session creation

This section defines common service types for registration, update and authentication of a user's second factor to support session creation based on the user's two factors.

The output of session creation is:

- session key: a key suitable for direct use as the CEK in the 2FA protection mode in use; its length and parameters are determined by that mode's encryption algorithm. This key MUST be uniformly distributed, MUST be unique per session, and MUST provide forward secrecy.
- session identifier: an identifier of the session key and the properties bound to it.
- context: the context under which the session is exchanged.
- task: an optional identifier of the task to be performed within the session.
- session expiration: the time at which the session expires, regardless of whether its task has completed.

A second-factor authentication mechanism that already outputs a key meeting these requirements (for example, the session key produced by OPAQUE [RFC9807]) MAY use that key directly as the session key. Otherwise, the mechanism MUST derive a suitable key from its output, for example using HKDF [RFC5869].

### Request parameters

These request parameters are defined for use in the defined service types for second factor establishment and session creation.

- `protocol` : (**string**) - Identifier of the protocol used for two-factor authentication. This parameter defines the content of the `p_data` parameter in both the request and the response.
- `state` : (**string**) - Identifier of the state of the protocol exchange
- `authorization` : (**byte array**) - Authorization data for registration of a new second factor
- `authorization_type` : (**string**) - The type of authorization data provided in the `authorization` parameter
- `task` : (**string**) - The requested session task used to determine the set of operations that are suitable for a created session
- `session_duration` : (**integer**) - The requested max duration of the created session in seconds
- `p_data` : (defined by protocol) - The protocol-specific request data. Its content is defined by the selected protocol and the current `state`, and MAY be a string, an object, or null.

### Response parameters

These response parameters are defined for use in the defined service types for second factor establishment and session creation.

- `success` : (**boolean**) - Indicates whether the server accepted and successfully processed the exchange. This member MUST be present in every response.
- `p_data` : (defined by protocol) - The protocol-specific response data for the current protocol and `state`. Its content is defined by the selected protocol and MAY be a string, an object, or null.
- `session_id` : (**string**) - The session identifier of a created session
- `task` : (**string**) - Confirming the session task set in the session request
- `session_expiration_time` : (**integer**) - The latest time this session will end expressed as seconds since epoch

### Member presence

Each service type specifies, in the tables below, which members appear in its requests and responses. Presence depends on the member, on the position of the exchange within the protocol's sequence, and, for responses, on whether the server reports success.

The exchange position is one of:

- `first`: the first exchange of the protocol.
- `last`: the concluding exchange of the protocol.
- `all`: every exchange.
- `protocol` : presence is defined by the protocol.

A protocol that completes in a single exchange treats that exchange as both the first and the last.

The presence rule is one of:

- `required`: the member MUST be present.
- `optional`: the member MAY be present.
- `required on success`: the member MUST be present when `success` is `true`, and MUST be absent otherwise.
- `required if requested`: the member MUST be present when the corresponding member was present in the request.

A response with `success` set to `false` contains only the `success` member; the presence rules in the tables below describe the success path.

### Service types

The following service types are defined in this section

- `create_session`: Authenticates the user's two factors and creates a session
- `2fa_registration`: Register a user's second factor
- `2fa_update`: Update a user's second factor

These service types are designed to allow any suitable protocol for authentication, registration and updates of the user's second factor. These service types have defined data structures as defined below.


#### `create_session` Service type

This service type is used to create a session based on authentication of the user's two factors. This service type MUST be exchanged using 1FA protection mode.

The `create_session` request contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `protocol` | all | required |
| `p_data` | all | required |
| `state` | all | required |
| `session_duration` | first | optional |
| `task` | first | optional |

If `session_duration` is not specified, the server MUST use a default value.

The `create_session` response contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `success` | all | required |
| `session_id` | all | required on success |
| `p_data` | all | required on success |
| `task` | last | required if requested |
| `session_expiration_time` | last | required on success |

The `session_id` identifies the session this exchange is bound to and attempts to create. It MUST be unique within the context and is returned in every response of the exchange. A returned `session_id` is NOT an indication that the session has been created; that is determined by `success` and the protocol data in the concluding response.

#### `2fa_registration` Service type

This service type is used to register a user's second factor. This service type MUST be exchanged using 1FA protection mode.

The `2fa_registration` request contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `protocol` | all | required |
| `p_data` | all | required |
| `state` | all | required |
| `authorization` | protocol | required |
| `authorization_type` | protocol | optional |

The `authorization` member provides out-of-band authorization that the user is authorized to register a second factor. Its content is defined by `authorization_type`.

NOTE: `authorization` is carried in the last exchange rather than the first so that protocols with stateless registration are supported uniformly. OPAQUE, for example, processes the `evaluate` (first) exchange without retaining server state; requiring authorization in the first exchange would force the server to keep state across the exchange. Placing it in the last exchange, where the server commits the registration, keeps registration stateless-friendly for all protocols.

This specification defines the following `authorization_type` values:

- `otp` : The `authorization` parameter is a one-time password given to the user by out-of-band means.

The `2fa_registration` response contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `success` | all | required |
| `p_data` | all | required on success |

#### `2fa_update` Service type

This service type is used to update the user's second factor under the protection of the current 2 factors. This service type MUST be exchanged using 2FA protection mode. This means that a session must already exist that is bound to the user's current 2 factors. This session MUST be bound to a task with the value `2fa_update` which allows one exchange of the `2fa_update` service type under the 2FA protection mode. This ensures that the user MUST present its second factor as part of the process to update this factor.

The `2fa_update` request contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `protocol` | all | required |
| `p_data` | all | required |
| `state` | all | required |

The `2fa_update` response contains:

| Member | Exchange | Presence |
|--------|----------|----------|
| `success` | all | required |
| `p_data` | all | required on success |

### Defined authentication protocols

This specification defines the following authentication protocols:

- `opaque`: Uses OPAQUE [RFC9807] to send a password knowledge proof to the server. This SHOULD be used for server-side password checks.
- `fido2`: Proves the second factor with a roaming WebAuthn authenticator. This mode SHOULD be used for device-attested flows using a FIDO2 Authenticator.

#### OPAQUE protocol

Use of the OPAQUE protocol option is identified by the protocol identifier `opaque`.

OPAQUE needs two roundtrips to complete registration or authentication and uses the following defined state identifiers in the context of this protocol:

- `evaluate` - Identifies the initial server evaluation state where the server evaluates the blinded OPRF data.
- `finalize` - Identifies the final state where registration or authentication is finalized.

##### `create_session`

Protection mode MUST be 1FA.

The following OPAQUE data is exchanged between the client and server:

| State | Direction | `p_data` content |
|-------|--------|------------------|
| `evaluate` | Request | AKE message 1 as Base64 encoded string |
| `evaluate` | Response | AKE message 2 as Base64 encoded string |
| `finalize` | Request | AKE message 3 as Base64 encoded string |
| `finalize` | Response | null |

##### `2fa_registration`

Protection mode MUST be 1FA.

Authorization data MUST be present in the `finalize` state of the protocol and MUST NOT be provided in the `evaluate` state.

The following OPAQUE data is exchanged between the client and server:

| State | Direction | `p_data` content |
|-------|--------|------------------|
| `evaluate` | Request | Registration request as Base64 encoded string |
| `evaluate` | Response | Registration response as Base64 encoded string |
| `finalize` | Request | Registration record as Base64 encoded string |
| `finalize` | Response | null |

##### `2fa_update`

Protection mode MUST be 2FA.

When OPAQUE is used in `2fa_update`, the data exchanged between the client and server is the same as in `2fa_registration`. The only difference is that the exchange is sent in 2FA protection mode, protected by the previous second-factor session key, and therefore does not need to provide any authorization data.

#### FIDO2 Authenticator protocol

Use of the FIDO2 Authenticator protocol option is identified by the protocol identifier `fido2`.

The second factor is established and verified locally by the user's FIDO2 authenticator. The resulting device attestation is verified by the server.

The mechanism relies on two complementary signatures: the JWS signature, which demonstrates possession, and a WebAuthn assertion carried inside data, which demonstrates user verification.

Every exchange is signed as an `ES256` JWS by the context signing key (CSK). In a platform or smartphone deployment the CSK is the platform's registered signing key and signs the JWS directly. In a roaming FIDO2 deployment the CSK is held by the FIDO2 authenticator, and the JWS signature is produced over the JWS signing input using the WebAuthn sign extension [WebAuthn-sign] (a raw signature over the supplied input). Either way the result is an ordinary ES256 JWS.

The second factor is demonstrated by a regular WebAuthn assertion whose authenticator data has the user-verification (UV) flag set. The server requests UV; the authenticator prompts for a PIN or biometric and sets the UV flag in the assertion. The assertion is carried inside the `p_data` of a `fido2` request.

To complete the second-factor check the server MUST:

1. Verify the assertion signature under the CSK registered for the context.
2. Verify that the UV flag is set.

There is no server-side password-verification object for this mechanism; registration enrols the WebAuthn credential itself.

The following defined state identifiers are used in the context of this protocol:

- `challenge` - Establish a challenge for the second factor authentication.
- `finalize` - Provide a WebAuthn signature that proves the second factor.

The `p_data` content for each state is defined per service type below. The session-key exchange used by `create_session` (the ephemeral keys and the session-key derivation) is out of scope of this revision and is defined separately.

##### `create_session`

Protection mode MUST be 1FA.

FIDO2 authentication requires two round-trips; the first to establish a challenge, the second to create a WebAuthn signature that proves the second factor and to negotiate the `2FA` session.

The following data is exchanged between the client and server:

| State | Direction | `p_data` content |
|-------|--------|------------------|
| `challenge` | Request | Authentication challenge request as JSON object |
| `challenge` | Response | Authentication challenge response as JSON object |
| `finalize` | Request | Authentication finalize request as JSON object |
| `finalize` | Response | Authentication finalize response as JSON object |

The `challenge` request `p_data` is `null`.

The `challenge` response `p_data`:

~~~json
{
  "challenge": "<base64 challenge, at least 16 bytes>",
  "token": "<opaque server state token>",
  "user_verification": "required"
}
~~~

- `challenge`: the WebAuthn challenge to be signed in the assertion.
- `token`: opaque server state bound to the challenge, echoed by the client in the `finalize` request so the server need not retain challenge state.
- `user_verification`: the WebAuthn user-verification requirement; MUST be `required`.

The `token` is an authenticated encryption of the server's challenge state under a key known only to the server. The server MUST encrypt at least the `challenge`, the `iat`, the `client_id`, and the `context`, so that the server can, on `finalize`, recover the issued challenge and confirm it was issued to the same client and context. The encryption algorithm is the server's choice and has no interoperability impact, since the token is produced and consumed only by the server; `A256GCM` is RECOMMENDED. The server MUST ensure the token cannot be replayed beyond a single authentication, for example by enforcing the `iat` freshness window and unique IVs.

The `finalize` request `p_data`:

~~~json
{
  "token": "<token from the challenge response>",
  "assertion": {
    "client_epub : "<base64 client ephemeral public key for session derivation>",
    "credential_id": "<base64 credential id>",
    "authenticator_data": "<base64 authenticatorData>",
    "client_data": "<base64 clientDataJSON>",
    "signature": "<base64 signature>"
  }
}
~~~

The `finalize` response `p_data`:

~~~json
{
  "server_epub : "<base64 server ephemeral public key for session derivation>",
}
~~~


Both sides establish the negotiated `2FA` session key as follows:

1. Compute `ikm = ECDH(own ephemeral private key, peer ephemeral public key)`.
2. Derive the `2FA` session key `K = HKDF(ikm, salt, info, L)` where `salt` is message `nonce` for the `finalize` round, `info` is the DST concatenated with a transcript-binding hash, and `L` is 32 bytes. The DST MUST be r2ps-2fa_authentication-fido2. The transcript binding hash MUST be `SHA256(2fa_mode || client_epub || server_epub || task || fido2 assertion signature)`.

##### `2fa_registration`

Protection mode MUST be 1FA.

Authorization data MUST be present in the finalize state of the protocol and MAY be present also in the challenge state.

There is no server-side verification object to register for the `fido2` mechanism. Registration instead enrolls the WebAuthn UV-capable credential and binds it to the `client_id` for that security context. The request carries the result of the WebAuthn credential-creation ceremony (the attestation object and client data); the server validates it according to [WebAuthn] and stores the credential public key. The `authorization` field authorizes the enrolment, as for the other mechanisms.

The flow is double-round. The client first requests a challenge. It then runs the WebAuthn credential-creation ceremony using the challenge it received in round 1.

The following data is exchanged between the client and server:

| State | Direction | `p_data` content |
|-------|--------|------------------|
| `challenge` | Request | Registration challenge request as JSON object |
| `challenge` | Response | Registration challenge response as JSON object |
| `finalize` | Request | Registration finalize request as JSON object |
| `finalize` | Response | null |

The `challenge` request `p_data` MAY carry client capabilities or preferences; otherwise it is `null`.

Note: Consider if this specification should define a structure for client capabilities and preferences.

The `challenge` response `p_data`:

~~~json
{
  "challenge": "<base64 challenge, at least 16 bytes>"
}
~~~

The `finalize` request `p_data`:

~~~json
{
  "credential_id": "<base64 credential id>",
  "attestation_object": "<base64 attestationObject>",
  "client_data": "<base64 clientDataJSON>"
}
~~~

On receiving the `finalize` request, the server MUST validate the attestation according to [WebAuthn]. Specifically, the server MUST:

1. Parse `client_data` (the `clientDataJSON`) and verify that its `type` field is exactly `"webauthn.create"`.
2. Verify that the `challenge` in `client_data` matches the `challenge` issued in the `challenge` response.
3. Verify that the `origin` in `client_data` matches the Relying Party's expected origin.
4. Decode `attestation_object` and verify that the `rpIdHash` in the authenticator data is the SHA-256 hash of the Relying Party ID.
5. Verify that the User Present (UP) flag in the authenticator data is set.
6. Verify that the User Verified (UV) flag in the authenticator data is set.
7. Verify the attestation statement's signature using the verification procedure for the attestation format.

On success, the server extracts the credential identifier and credential public key from the attested credential data, and binds the `credential_id` and public key to the `client_id` in that security context. This credential is the one from which UV assertions are required in subsequent `create_session` exchanges.

On success, the `finalize` response `p_data` is `null`.

##### `2fa_update`


When the FIDO2 Authenticator protocol is used in `2fa_update`, the data exchanged between the client and server is the same as in `2fa_registration`. The only difference is that the exchange is sent in 2FA protection mode, protected by the previous second-factor session key, and therefore does not need to provide any authorization data.

# Hardening of knowledge factors

## Purpose and applicability

A knowledge factor such as a short PIN has a small value space. This section specifies two complementary mechanisms that raise the cost of
testing candidate values:

1. Key stretching, which increases the cost of each guess.
2. A Device-Enhanced Password (DE-PWD) makes each guess depend on a client-held secret.
Neither mechanism increases the entropy of the knowledge factor. DE-PWD makes OPAQUE’s password input depend additionally on a client-held high entropy secret.

These mechanisms apply to the server-verified knowledge factor used with the `opaque` protocol.

## Key stretching in OPAQUE

OPAQUE applies a key stretching function (KSF) to the OPRF output on the client (Section 10.8 of [RFC9807]). Deployments SHOULD select a memory-hard KSF, with parameters suited to their client platforms, from those supported by their OPAQUE configuration. The KSF and its parameters MUST be identical at registration and authentication.

Key stretching does not prevent offline dictionary attacks by an attacker who obtains the server's OPRF secrets and credential records (Section 10.11 of {{RFC9807}}). Deployments that use short PINs SHOULD therefore also use a DE-PWD.

## Device-enhanced passwords

A device-enhanced password (DE-PWD) is derived on the client from the knowledge factor and a client-held secret. It replaces the knowledge factor as OPAQUE's password input. The client MUST apply the same derivation at registration, at authentication, and when re-registering after a change of knowledge factor.

A DE-PWD is RECOMMENDED where hardening must remain effective after disclosure of the server's OPRF secrets and credential records. The client MUST NOT transmit the DE-PWD or any secret intermediate value; only the resulting OPAQUE messages are sent. This protection assumes that the attacker cannot obtain the client-held secret or obtain DE-PWD values for arbitrary password guesses through any interface available to the attacker.

The client-held secret SHOULD be protected by device hardware. The profile below uses the private client context agreement key (CAK). An implementation that uses the CAK both for this derivation and for R2PS key agreement MUST keep the two uses separate and MUST NOT expose raw shared secrets.

### Device enhanced passwords using P-256

This derivation applies to contexts whose client CAK is a P-256 key. It combines the hash to curve `P256_XMD:SHA-256_SSWU_RO_` suite (Section 8.2 of {{RFC9380}}), P-256 scalar multiplication, and HKDF-SHA-256 {{RFC5869}}.

The inputs are:

- `password`: the UTF-8 encoding of the knowledge factor. This derivation performs no normalization, trimming, or case folding.
- `d`: the private scalar of the client's registered P-256 CAK.
- `context`, `client_id`: the UTF-8 encodings of the corresponding R2PS identifiers.

`||` denotes byte-string concatenation. `LP(x)` denotes the length of `x` in octets as a 4-octet unsigned big-endian integer, followed by
`x`. Inputs whose length cannot be so encoded MUST be rejected.

The client computes `de_pwd` as follows:

1. `P = hash_to_curve(password)`, using the suite above with either the suite's default DST or an application specific one, encoded as ASCII without a terminating zero octet.
2. `Q = d * P`. If `P` or `Q` is the point at infinity, the derivation MUST fail.
3. `ikm` is the affine x-coordinate of `Q`, encoded as a 32-octet unsigned big-endian integer, including leading zero octets. This is the raw ECDH shared secret.
4. `prk = HKDF-Extract(salt, ikm)`, using SHA-256 and a `salt` of 32 zero octets.
5. `de_pwd = HKDF-Expand(prk, info, 32)`, where `info = LP(context) || LP(client_id)`.

The 32-octet `de_pwd` MUST be used directly as OPAQUE's password input. OPAQUE's KSF is applied at its normal position in the protocol.

The derivation and its inputs MUST be fixed for the registered credential. Use of this derivation is part of the context configuration.

# Compliance tokens and RATS {#compliance-rats}

The `compliance_token`, `compliance_proof`, and `compliance_token_type` request members let a client show that it meets a server's compliance policy, such as device integrity, operating-system or application version and integrity, or key protection. This follows the passport model of the Remote ATtestation procedureS (RATS) architecture [RFC9334]: a Verifier tests the client and issues the token, and the R2PS server, as Relying Party, appraises it against its own policy. The Entity Attestation Token (EAT) [RFC9711] is one common token format; others can be used equally well. What the Verifier tests, and how the server comes to trust it, are out of scope.

A token is obtained once and presented on many requests; its validity alone does not show that the party presenting it now is the one it describes. The token can therefore be bound to the presenter, in several ways:

- Bound to a key, typically a device key. An EAT, for example, may be key-bound through a confirmation (`cnf`) claim [RFC7800] [RFC8747]. When a token is key-bound in this way, the client can provide proof of possession of that key in `compliance_proof`. Such proof-of-possession data can be a signature, produced with the bound key, over data unique to the request, such as the request `nonce`.
- Bound to an identity that the request itself verifies. Because every request is signed and thereby proves the client's identity, a reusable token bound to that identity needs no separate proof; the request's own signature binds it to the presenter.

This specification mandates no particular token, binding, or proof. The `compliance_token_type` identifies the profile in use, agreed between the parties.

# Definition of service types

This document defines only the basic service types needed to establish two-factor protected sessions and to register and update the user's second factor (a knowledge or biometric factor): `create_session`, `2fa_registration`, and `2fa_update`.

Other service data exchanges — for example server-side HSM key generation, signing with a server-side HSM key, and similar operations — require new service types, each with its own data structure and protection mode, agreed between the client and the server. Other documents may define new service types for use with this protocol.

The identifiers used for service types need only be unambiguous within the client and server agreement in which they are used; ensuring this is the responsibility of the agreeing parties.

NOTE: A registry for service type identifiers is requested from IANA in {{iana}}, giving a common place to register service types intended for use across deployments.

# Security Considerations {#security-considerations}

The security of R2PS rests on the context keys held by the client and the server. This document does not define how a client is bootstrapped or how the parties come to hold each other's trusted public keys; that exchange, and the ongoing storage of the keys, MUST be done in a secure and trustworthy manner, because every guarantee this protocol provides follows from it. Disclosure or misuse of a client's private context keys undermines all of the protection the parties rely on.

A low-entropy knowledge factor, such as a short PIN, increases the chance of success for exhaustive guessing and raises the protection required for server-side secrets. When low-entropy knowledge factors are used, implementers SHOULD consider the strategies described in the "Hardening of knowledge factors" section.

Using the same knowledge factor in more than one security context is dangerous when those contexts protect it to different degrees. An adversary who obtains the factor where it is least protected could reuse it in a more security-critical context. This risk is heightened if the adversary has gained possession of the user's device before the factor can be revoked.

Accepting clients that do not meet minimum policy requirements can compromise a client and the keys it holds. Where a deployment's security policy requires it, a server is RECOMMENDED to require a compliance token ({{compliance-rats}}) demonstrating that the client meets minimum security requirements for its operating system, key store, and critical applications before relying on the client.

Because the JWE is the outer object, a server performs decryption work before it can authenticate the inner signature, so unauthenticated requests can be used to consume server resources. A deployment of this protocol should consider applying suitable measures to mitigate the risk of denial-of-service attacks.

Each service type requires a specific protection mode, signalled in the JWE header. A server needs to confirm that a request's protection mode matches the mode its service type requires and reject it otherwise; without this check, an operation that requires two-factor protection could be accepted under one-factor protection.

In 2FA mode the session key is used directly as the content-encryption key for every message, in both directions, so a fresh, non-repeating per-message IV is essential. Because GCM is counter-based, reusing an IV under the session key repeats the keystream. Repeating IV values therefore undermines the protection properties of the encryption layer of the protocol. The sender MUST generate a new random 96-bit IV for every encrypted message to get the full confidentiality protection offered by the protocol.

The security considerations of the cryptographic building blocks used by this protocol apply: JSON Web Signature [RFC7515], JSON Web Encryption [RFC7516], and the JOSE algorithms [RFC7518]; HKDF [RFC5869] where a profile derives a session key; OPAQUE [RFC9807] for the `opaque` mechanism; WebAuthn for the `fido2` mechanism; and the RATS architecture [RFC9334] and the Entity Attestation Token [RFC9711] for compliance tokens.

# IANA Considerations {#iana}

## R2PS Service Types registry

IANA is requested to create a new registry group "Remote Two-Factor Protected Services (R2PS)" containing the "R2PS Service Types" registry.

The registration policy for this registry is Specification Required [RFC8126]. Each entry has the following fields:

- Service Type: the identifier string carried in the `type` member of a request.
- Description: a short description of the service type.
- Reference: the specification that defines the service type.

The initial contents of the registry are:

| Service Type | Description | Reference |
|------------------|------------------------------------------------------------|---------------|
| `create_session` | Authenticate the user's two factors and create a session   | This document |
| `2fa_registration` | Register the user's second factor                        | This document |
| `2fa_update`     | Update the user's second factor                            | This document |

When reviewing a registration request, the Designated Expert verifies that a permanent and publicly available specification defines the service type, including its identifier, the request and response data it carries, and the protection mode it requires, and that the requested identifier is unambiguous and not already registered.

## Media Type registrations

IANA is requested to register the following media types in the "Media Types" registry [RFC6838]. These correspond to the JWS and JWE `typ` header parameter values defined in this document; as noted in [RFC7515], the `application/` prefix is omitted when such a value is carried in a `typ` header.

The four media types share the following registration template, differing only in the Subtype name and the description under "Applications that use this media type":

- Type name: application
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; the value is a JWS or JWE object in compact serialization [RFC7515] [RFC7516].
- Security considerations: See {{security-considerations}} of this document, as well as [RFC7515] and [RFC7516].
- Interoperability considerations: N/A
- Published specification: This document.
- Fragment identifier considerations: N/A
- Additional information: Deprecated alias names: N/A; Magic number(s): N/A; File extension(s): N/A; Macintosh file type code(s): N/A
- Person & email address to contact for further information: The authors of this document.
- Intended usage: COMMON
- Restrictions on usage: N/A
- Author: The authors of this document.
- Change controller: IETF

The Subtype names and descriptions are:

| Subtype name | Description |
|-------------------------|---------------------------------------------------------|
| `r2ps-request+jws`      | An R2PS inner JWS carrying a service request.           |
| `r2ps-response+jws`     | An R2PS inner JWS carrying a service response.          |
| `r2ps-1fa`              | An R2PS outer JWE in `1FA` protection mode.             |
| `r2ps-2fa`              | An R2PS outer JWE in `2FA` protection mode.             |


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
