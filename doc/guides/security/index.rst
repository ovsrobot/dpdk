..  SPDX-License-Identifier: BSD-3-Clause

Security Support Guide
======================

This document describes the security features available in the DPDK.
This guide will provides information on each protocol,
including supported algorithms, practical implementation details, and references.

By detailing the supported algorithms and providing insights into each
security protocol, this document serves as a resource for anyone looking
to implement or enhance security measures within their DPDK-based environments.



Related Documentation
---------------------

Here is a list of related documents that provide detail of each library,
its capabilities and what level of support it currently has within DPDK.

* :doc:`Crypto Device Drivers <../cryptodevs/index>`
  This section contains information about all the crypto drivers in DPDK,
  such as feature support availability, cipher algorithms and authentication
  algorithms.

* :doc:`Security Library <../prog_guide/rte_security>`
  This library is the glue between ethdev and and crypto dev. It includes low-level supported protocols such as MACsec, TLS, IPSec, and PDCP.

* Protocols: These include two supported protocols in DPDK.
  * :doc:`IPSec Library <../prog_guide/ipsec_lib>`
  * :doc:`PDCP Library <../prog_guide/pdcp_lib>`


Protocols
---------

QUIC
~~~~

QUIC (Quick UDP Internet Connections) is a transport layer network
protocol designed by Google to improve the speed and reliability of web connections.
QUIC is built on top of the User Datagram Protocol (UDP) and uses a combination of
encryption and multiplexing to achieve its goals. The protocol's main goal is to
reduce latency compared to Transmission Control Protocol (TCP). QUIC also
aims to make HTTP traffic more secure and eventually replace TCP and TLS on
the web.

Media over QUICK (MoQ) is a new live media protocol powered by QUIC. It is
a TCP/UDP replacement designed for HTTP/3.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/QUIC

**Standard Link**
        * https://quic.video/

**Level of Support in DPDK**
        * Not supported in DPDK.

**Pros**
        * Useful for time-sensitive application like online gaming or video streaming.
        * Can send multiple streams of data over a single channel.
        * Automatically limits the packet transmission rate to counteract load peaks and avoid overload, even with low bandwidth connections.
        * Uses TLS 1.3, which offers better security than others.
        * Fast data transfer.
        * Combines features of TCP, such as reliability and congestion control, with the speed and flexibility of UDP.

**Cons**
        * Has more complex protocol logic, which can result in higher CPU and memory usage compared to TCP.
        * May result in poorer transmission rates.
        * Requires changes to client and server, making it more challenging to deploy that TCP.
        * Not yet as widely deployed as TCP.


MACSec
~~~~~~

MACsec (accelerated by Marvell) is a network security standard that operates
at the medium access control layer and defines connectionless data confidentiality
and integrity for media access independent protocols. It is standardized by the
IEEE 802.1 working group.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/IEEE_802.1AE

**Standard Link**
        * https://1.ieee802.org/security/802-1ae/

**Level of Support in DPDK**
        * Supported in DPDK + 'Sample Application <https://doc.dpdk.org/guides/sample_app_ug/l2_forward_macsec.html>'

**Supported Algorithms**
        * As specified by MACsec specification: AES-128-GCM, AES-256-GCM

**Drivers**
        * Marvell cnxk Ethernet PMD which supports inline MACsec

**Facts**
        * Uses the AES-GCM cryptography algorithm
        * Works on layer 2 and protects all DHCP and ARP traffic
        * Each MAC frame has a separate integrity verification code
        * Prevents attackers from resending copied MAC frames into the network without being detected
        * Commonly used in environments where securing Ethernet traffic between devices is critical, such as in enterprise networks, data centers and service provider networks
        * Applications do not need modification to work with IPsec

**Cons**
        * Only operates at Layer 2, so it doesn't protect traffic beyond the local Ethernet segment or over Layer 3 networks or the internet
        * Data is decrypted and re-encrypted at each network device,
which could expose data at each point
        * Can't detect rogue devices that operate on Layer 1
        * Relies on hardware for encryption and decryption, so not all network devices can use it


IPSec
~~~~~

IPsec (accelerated by Intel, Marvell, Netronome, NXP) allows secure communication
over the internet by encrypting data traffic between two or more devices or networks.
IPsec works on a different layer than MACsec, at layer 3.

**Wikipedia Link**
        * https://en.wikipedia.org/wiki/IPsec

**Standard Link**
        * https://datatracker.ietf.org/wg/ipsec/about/

**Level of Support in DPDK**
        * Supported
        * High-level library and sample application
        * https://doc.dpdk.org/guides/sample_app_ug/ipsec_secgw.html

**Supported Algorithms**
        * AES-GCM and ChaCha20-Poly1305
        * AES CBC and AES-CTR
        * HMAC-SHA1/SHA2 for integrity protection and authenticity

**Pros**
        * Uses public keys to create an encrypted, authenticated tunnel to resources
        * Offers strong security, scalability, and interoperability
        * IPsec can work across routers
        * Applications do not need modification to work with IPsec

**Cons**
        * Can be simple to apply but complex to use. It can also be difficult to configure and place an administrative burden on network administrators
        * Can impact network performance because it encrypts all traffic and uses strict authentication processes, both of which consume network bandwidth and increase data usage
        * IPsec relies on the security of public keys. Key management protocol is not part of DPDK but DPDK provides asymmetric crypto APIs which are required for key generation


TLS
~~~

Transport Layer Security (TLS) is a cryptographic protocol that operates at the fifth application layer.
It encrypts data sent between web applications and servers, such as when a web browser loads a website.
TLS can also be used to encrypt other types of communication, including: Email, Voice over IP (VoIP),
File transfers, Video/audio conferencing, and Internet services like DNS and NTP.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/Transport_Layer_Security

**Standard Link**
        * https://datatracker.ietf.org/doc/html/rfc8446 - TLS 1.3
        * https://datatracker.ietf.org/doc/html/rfc5246 - TLS 1.2
        * https://datatracker.ietf.org/doc/html/rfc9147/ - DTLS 1.3

**Level of Support in DPDK**
        * DPDK supports TLS/DTLS record processing via rte_security APIs

**Pros**
        * Considered one of the strongest encryption protocols available
        * Doesn't require parties to encrypt the content they exchange
        * Universally deployable, doesn't rely on specific operating systems or applications
        * Can reduce the risk of phishing attacks

**Cons**
        * May not work with complex proxy caching systems
        * Adding a server to handle encryption before it gets to the caching server can require additional costs
        * TLS can be vulnerable to attacks and data leaks, including downgrade attacks, weak ciphers, and programming errors
        * The added layer of security that TLS provides can come at the cost of speed


TLS Handshake
~~~~~~~~~~~~~

TLS Handshake is the process that kicks off a communication session that uses TLS.
During a TLS handshake, the two communicating sides exchange messages to acknowledge
each other, verify each other, establish the cryptographic algorithms they will use,
and agree on session keys.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake

**Standard Link**
        * https://datatracker.ietf.org/doc/html/rfc8446#section-4

**Level of Support in DPDK**
        * Handshake as protocol is not implemented in DPDK. However, it supports asymmetric crypto APIs, which can be used by the protocol.

**Pros**
        * TLS 1.3 also supports an even faster version of the TLS handshake that does not require any round trips, or back-and-forth communication between client and server, at all.

**Cons**
        * Unknown.


TLS Record
~~~~~~~~~~

TLS Record (accelerated by Marvell) Protocol is a layer of the TLS protocol
that protects application data using keys created during the TLS handshake.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/Transport_Layer_Security (Scroll to TLS Record)

**Standard Link**
        * https://datatracker.ietf.org/doc/html/rfc8446#section-5

**Level of Support in DPDK**
        * Supported.

**Supported Algorithms**
        * TLS 1.3 - AES-GCM-128, AES-GCM-256, CHACHA20-POLY130
        * TLS1.2/DTLS 1.2 - AES-GCM-128, AES-GCM-256, AES-CBC-128-SHA1,
        * AES-128-CBC-SHA256, AES-256-CBC-SHA1, AES-256-CBC-SHA256, AES-256-CBC-SHA384, 3DES-CBC-SHA1-HMAC, NULL-SHA1-HMAC, CHACHA20-POLY1305

**Pros**
        * TLS 1.3 also supports an even faster version of the TLS handshake that does not require any round trips, or back-and-forth communication between client and server, at all

**Cons**
        * Unknown if this differs from cons listed under TLS.


PDCP
~~~~

Packet Data Convergence Protocol (PDCP) is a sublayer in the LTE radio protocol stack
that provides security and integrity protections to Protocol Data Units (PDU) in both
the control and data planes. PDCP is located between the Radio Link Control (RLC) layer
and the upper layers of the network, such as the IP layer.


**Wikipedia Link**
        * https://en.wikipedia.org/wiki/Packet_Data_Convergence_Protocol

**Standard Link**
        * https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1177

**Level of Support in DPDK**
        * Supported. High-level library.
        * rte_security based PDCP sessions are also supported

**Supported Algorithms**
        * Encryption algo - NULL, AES-CTR, SNOW, ZUC
        * Authentication algo - NULL, AES-CMAC, SNOW, ZUC

**Supported Drivers**
        * Drivers supporting rte_security PDCP:
        * XPdpaa2_sec, dpaa_sec
        * Drivers supporting pdcp lib
        * Marvell cnxk
        * Intel - QAT, ipsec_mb

**Pros**
        * Compresses the IP header of user plane packets to reduce overhead and optimize bandwidth usage over the radio interface. This is particularly important in mobile networks where radio resources are limited and efficiency is critical
        * PDCP encrypts and decrypts user plane data to ensure confidentiality and integrity of data transmitted over the air interface
        * Has the option of interoperability between different generations of mobile networks (e.g., LTE and 5G) and compatibility with IP-based networks

**Cons**
        * Limitations currently unclear


PSP
~~~

PSP is a TLS-like protocol created by Google for encrypting data in transit between data centers.
It uses concepts from IPsec ESP to create an encryption layer on top of IP, and supports non-TCP
protocols like UDP. Google uses PSP along with other protocols, such as TLS and IPsec, depending on the use case.


**Standard Links**
        * https://cloud.google.com/blog/products/identity-security/announcing-psp-security-protocol-is-now-open-source?hl=en
        * https://github.com/google/psp

**Level of Support in DPDK**
        * Not supported in DPDK, but algorithms are supported.
        * rte_security based PDCP sessions are also supported

**Supported Algorithms**
        * AES-GCM-128
        * AES-GCM-256
        * AES-GMAC

**Pros**
        * PSP is transport-independent and can be offloaded to hardware
        * It does not mandate a specific key exchange protocol
        * Enables per-connection security by allowing an encryption key per layer-4 connection (such as a TCP connection)

**Cons**
        * Offers few choices for the packet format and the cryptographic algorithms


Wireguard
~~~~~~~~~

Wireguard is a open-source tunneling protocol.

**Wikipedia Link**
        * https://en.wikipedia.org/wiki/WireGuard

**Standard Link**
        * https://www.wireguard.com/

**Level of Support in DPDK**
        * Not supported at this time, but algorithms are supported.

**Supported Algorithms**
        * ChachaPoly SW Driver

**Pros**
        * Faster than most VPNs
        * straightforward with a lean codebase
        * Works with various operating systems such as Linux, Windows, macOS, Android, and iOS
        * Quick connections (good for mobile environments)

**Cons**
        * Has been rapidly adopted, but still a new, young protocol.
        * May not have the same level of extensive real-world testing and deployment as other VPNs.
        * Widely supported, but compatibility may still be an issue.
