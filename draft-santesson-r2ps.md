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
  RFC7515:
  RFC7516:
  RFC9807:

informative:

--- abstract

This document defines a generic service exchange protocol where service exchange data is protected and bound to a physical user using 1 or 2 factors (1FA and 2FA). The protocol facilitates registration and verification of either a knowledge-factor or a biometric factor under 1 factor protection as means of achieving 2 factor protection.

--- middle

# Introduction

Several protocols are capable of authentication and key exchange based on a password.

{fill in information about aPAKE}

EU has defined a level of assurance framework for user authentication based on en eID [1502]. On the highest assurancelevel (LoA High) the key used to authenticate the user must be protected by tamper resistant hardware (HSM) that protects against an adversary with high attack potential. This framework further specifies that access to the protected authentication key must be protected by 2-factor authentication.

The EU Digital Identity Wallet (EUDI Wallet) defined by the new eIDAS regulation [{add ref}] specifies that HSM protection when the wallet provides authentication on LoA High, must be realized by a Wallet Secure Cryptographic Application (WSCA) that includes a Wallet Secure Cryptographic Device (WSCD).

The WSCA is a software module responsible for controlling access to keys protected by the hardware module (WSCD).

Some wallet actions, such as presenting a Verifiable Presentation on LoA High, requires the user to provide a knowledge-factor or a biometric factor together with a possession factor to access necessary keys. This action may require one or more service request to a backend service such as the WSCA.

This protocol is designed as a framework for such service exchanges based on two-factor user authentication that allows the client and server to use any suitable mechanism for user authentication.

For this reason this protocol defines to protection profiles (1FA and 2FA). The 1FA mode allows device authenticated exchange before the user 2nd factor has been validated, and the 2FA mode provides user authenticated exchange based on a session key derived from authentication of the 2nd factor.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Basic structure

The basic structure of R2PS is a simple stateless request response protocol. The request and response data is a JSON Web Encryption object (JWE) [RFC7516] that includes a JSON WEB Signature object (JWS) [RFC7515].
The JWS contains a basic request and response structure and service data as defined by a service type identifier.

{draw an IETF style text based image illustrating the basic structure}

The protocol allows the client and server to agree on any number of server type identifiers, each having its own defined data structure for request and response data.

While the base protocol structure has no state, the inner service data structure may be used in a process that requires state. This is defined by each service type.

This specification defines default service types for negotiation and verification of the user's 2nd factor.
Other service types MAY be defined by other documents.

## Bootstrapping the protocol

The protocol is designed to serve the need for service exchange with many different server resources each cryptographically separated from each other.

This is achieved by meas of separate "context keys" at the client and server. Each context key is identified by a context id and represents a security context that is cryptographically separated from other security contexts.

The manner through which the client and the server has shared trusted context keys is out of scope of this specification.

Initial registration of a user's 2nd factor may need authorization data that was provided to the user by out-of-band means. This MAY be a one-time password or other authorization data that asserts that the user factor is provided by the intended user. The protocol facilitates exchange of such authorization data in the registration process, but the composition of this data and the means for providing this data to the user is out of scope for this specification. 

# R2PS Protocol

## Outer JWE object

The outer JWE object provides encryption protection for the exchanged service data.

Two encryption modes:

- 1FA, based on a key derived from server or client recipient key and an ephemeral sender key.
- 2FA, based on a negotiated session key, derived from verification of the user's 2 factors.

{describe JWE structure}


## Inner JWS object

The inner JWS object is signed using the sender context key.

{describe the JWS object structure}


# Security Considerations

Security considerations goes here

# IANA Considerations

IANA considerations goes here


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
