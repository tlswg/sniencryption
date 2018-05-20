%%%
    Title = "SNI Encryption in TLS Through Tunneling"
    abbrev = "SNI Encryption in TLS"
    category = "std"
    docName= "draft-ietf-tls-sni-encryption-oldsolution-latest"
    ipr = "trust200902"
    area = "Network"
    date = 2017-08-29T00:00:00Z
    [pi]
    toc = "yes"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
    initials="C."
    surname="Huitema"
    fullname="Christian Huitema"
    organization = "Private Octopus Inc."
      [author.address]
      email = "huitema@huitema.net"
      [author.address.postal]
      city = "Friday Harbor"
      code = "WA  98250"
      country = "U.S.A"

    [[author]]
    initials="E."
    surname="Rescorla"
    fullname="Eric Rescorla"
    organization= "RTFM, Inc."
      [author.address]
      email= "ekr@rtfm.com"
      [author.address.postal]
      country = "U.S.A"

%%%


.# Abstract

This draft presents two potential TLS layer solutions
that might mitigate the attacks against SNI encryption.  
The first solution is based on TLS in TLS "quasi tunneling",
and the second solution is based on "combined tickets".
These solutions only require minimal extensions to the TLS
protocol.

{mainmatter}

# Introduction

The motivation for encrypting the Service Name Information (SNI)
extension in TLS is described in [@!I-D.ietf-tls-sni-encryption].
The current draft proposes two designs for SNI Encryption in TLS. 
Both designs hide a "Hidden Service" behind a "Fronting
Service". To an external observer, the TLS connections will appear to
be directed towards the Fronting Service. The cleartext SNI parameter
will document the Fronting Service. A second SNI parameter will be
transmitted in an encrypted form to the Fronting Service, and will
allow that service to redirect the connection towards the Hidden Service.

The first design relies on tunneling TLS in TLS, as
explained in (#snitunnel). It does not require TLS extensions,
but relies on conventions in the implementation of TLS 1.3 [@!I-D.ietf-tls-tls13]
by the Client and the Fronting Server.

The second design, presented in (#comboticket) removes the requirement for 
tunneling, on simply relies on Combined Tickets. It uses the extension
process for session tickets already defined in [@!I-D.ietf-tls-tls13].

This draft is presented as is to trigger discussions. It is expected that as the
draft progresses, only one of the two proposed solutions will be retained.

## Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC2119].

# SNI Encapsulation Specification {#snitunnel}

We propose to provide SNI Privacy by using a form of TLS encapsulation.
The big advantage of this design compared to previous attempts
is that it requires effectively no changes
to TLS 1.3. It only requires a way to signal to the Fronting Server
server that the encrypted application data is actually a ClientHello
which is intended for the hidden service. Once the
tunneled session is established, encrypted packets will
be forwarded to the Hidden Service without requiring
encryption or decryption by the Fronting Service.

## Tunneling TLS in TLS {#tlsintls}

The proposed design is to encapsulate a second Client Hello in the
early data of a TLS connection to the Fronting Service. To the outside,
it just appears that the client is resuming a session with the
fronting service.

~~~
  Client                  Fronting Service         Hidden Service
  ClientHello
  + early_data
  + key_share*
  + psk_key_exchange_modes
  + pre_shared_key
  + SNI = fronting
  (
   //Application data
   ClientHello#2
    + KeyShare
    + signature_algorithms*
    + psk_key_exchange_modes*
    + pre_shared_key*
    + SNI = hidden
  )
                    -------->
                         ClientHello#2
                         + KeyShare
                         + signature_algorithms*
                         + psk_key_exchange_modes*
                         + pre_shared_key*
                         + SNI = hidden  ---->

  <Application Data*>
  <end_of_early_data>    -------------------->  
                                                      ServerHello
                                                +  pre_shared_key
                                                     + key_share*
                                            {EncryptedExtensions}
                                            {CertificateRequest*}
                                                   {Certificate*}
                                             {CertificateVerify*}
                                                       {Finished}
                         <--------------------
  {Certificate*}
  {CertificateVerify*}
  {Finished}             ---------------------

  [Application Data]     <-------------------> [Application Data]


  Key to brackets:

  *  optional messages, not present in all scenarios
  () encrypted with Client->Fronting 0-RTT key
  <> encrypted with Client->Hidden 0-RTT key
  {} encrypted with Client->Hidden 1-RTT handshake
  [] encrypted with Client->Hidden 1-RTT key
~~~

The way this works is that the Fronting Server decrypts the *data* in the
client's first flight, which is actually ClientHello#2 from the
client, containing the true SNI and then passes it on to the Hidden
server. However, the Hidden Server responds with its own ServerHello
which the Fronting Server just passes unchanged, because it's actually the
response to ClientHello#2 rather than to ClientHello#1. As long as
ClientHello#1 and ClientHello#2 are similar (e.g., differing only in
the client's actual share (though of course it must be in the same
group)), SNI, and maybe EarlyDataIndication), then an attacker should
not be able to distinguish these cases -- although there may be possible
attacks through timing analysis, or by observing traffic between the
Fronting Server and Hidden Server if they are not colocated.

## Tunneling design issues {#tunnelissues}

The big advantage of this design is that it requires effectively no changes
to TLS. It only requires a way to signal to the Fronting
Server that the encrypted application data is actually a ClientHello
which is intended for the hidden service. 

The major disadvantage of this overall design strategy (however it's
signaled) is that it's somewhat harder to implement in the co-tenanted
cases than the simple schemes that carry the "real SNI" in an encrypted 
parameter of the Client Hello. That means that it's
somewhat less likely that servers will implement it "by default" and
more likely that they will have to take explicit effort to allow
Encrypted SNI. Conversely, however, these schemes (aside from a server
with a single wildcard or multi-SAN cert) involve more changes to TLS
to deal with issues like "what is the server cert that is digested
into the keys", and that requires more analysis, so there is an
advantage to deferring that. If we have EncryptedExtensions in the
client's first flight it would be possible to define a "Real SNI" extension
later if/when we had clearer analysis for that case.

Notes on several obvious technical issues:

1. How does the Fronting Server distinguish this case from where the initial
   flight is actual application data? See (#gatewaylogic) for some thoughts
   on this.

2. Can we make this work with 0-RTT data from the client to the Hidden
   server? The answer is probably yes, as discussed in (#tlsintlsearly).

3. What happens if the Fronting Server doesn't gateway, e.g., because
   it has forgotten the ServerConfiguration? In that case, the
   client gets a handshake with the Fronting Server, which it will have
   to determine via trial decryption. At this point the Fronting Server
   supplies a ServerConfiguration and the client can reconnect
   as above.

4. What happens if the client does 0-RTT inside 0-RTT (as in #2 above)
   and the Hidden server doesn't recognize the ServerConfiguration in
   ClientHello#2? In this case, the client gets a 0-RTT rejection and
   it needs to do trial decryption to know whether the rejection was
   from the Fronting Server or the Hidden server.

5. What happens if the Fronting Server is under a DOS attack, and chooses
   to refuse all 0-RTT data?

The client part of that logic, including the handling of question #3 above,
is discussed in (#tlsintlsclientreq).

### Fronting Server logic {#gatewaylogic}

The big advantage of this design is that it requires effectively no changes
to TLS. It only requires a way to signal to the Fronting
Server that the encrypted application data is actually a ClientHello
which is intended for the hidden service. The two most obvious
designs are:

- Have an EncryptedExtension which indicates that the inner
  data is tunnelled.
- Have a "tunnelled" TLS content type.

EncryptedExtensions would be the most natural, but they were removed
from the ClientHello during the TLS standardization. In (#tlsintls)
we assume that the second ClientHello is just transmitted as 0-RTT
data, and that the servers use some form of pattern matching to
differentiate between this second ClientHello and other application
messages.

### Early data {#tlsintlsearly}

In the proposed design, the second ClientHello is sent to the
Fronting Server as early data, encrypted with Client->Fronting
0-RTT key. If the Client follows the second ClientHello with
0-RTT data, that data could in theory be sent in two ways:

1. The client could use double encryption. The data is first
   encrypted with the Client->Hidden 0-RTT key, then
   wrapped and encrypted with the Client->Fronting 0-RTT key.
   The Fronting server would decrypt, unwrap and relay.

2. The client could just encrypt the data with the
   Client->Hidden 0-RTT key, and ask the server to blindly
   relay it.

Each of these ways has its issues. The double encryption
scenario would require two end of early data messages, one
double encrypted and relayed by the Fronting Server to the 
Hidden Server, and another sent from Client to Fronting Server,
to delimit the end of the double encrypted stream, and
also to ensure that the stream of messages is not distinguishable 
from simply sending 0-RTT data to the Fronting server. The 
blind relaying is simpler, and is the scenario described in
the diagram of (#tlsintls). In that scenario, the Fronting
server switches to relaying mode immediately after unwrapping
and forwarding the second ClientHello. However, the blind 
relaying requires the ClientHello to be isolated to a single record.
  
### Client requirements {#tlsintlsclientreq}

In order to use the tunneling service, the client needs to identify
the Fronting Service willing to tunnel to the Hidden Service. We can
assume that the client will learn the identity of suitable Fronting
Services from the Hidden Service itself.

In order to tunnel the second ClientHello as 0-RTT data, the client
needs to have a shared secret with the Fronting Service. To avoid the
trap of "well known shared secrets" described in (#sharedsecrets),
this should be a pair wise secret. The most practical solution is
to use a session resumption ticket. This requires that prior to
the tunneling attempt, the client establishes regular connections
with the fronting service and obtains one or several session resumption 
tickets.


# SNI encryption with combined tickets {#comboticket}

EDITOR'S NOTE: This section is an alternative design to (#snitunnel). As the
draft progresses, only one of the alternatives will be selected, and the
text corresponding to the other alternative will be deleted.

We propose to provide SNI Privacy by relying solely on
"combined tickets".
The big advantage of this design compared to previous attempts
is that it requires only minimal changes to implementations
of TLS 1.3. These changes are confined to the handling of the
combined ticket by Fronting and Hidden service, and to the signaling
of the Fronting SNI to the client by the Hidden service.
 
## Session resumption with combined tickets {#comboresume}

In this example, the client obtains a combined session resumption
ticket during a previous connection to the hidden service, and
has learned the SNI of the fronting service. The session
resumption will happen as follows:

~~~
  Client                    Fronting Service         Hidden Service
  ClientHello
  + early_data
  + key_share*
  + psk_key_exchange_modes
  + pre_shared_key
  + SNI = fronting
                    -------->
                         // Decode the ticket
                         // Forwards to hidden
                         ClientHello  ------->

  (Application Data*)  ---------------------->
                                                      ServerHello
                                                +  pre_shared_key
                                                     + key_share*
                                            {EncryptedExtensions}
                                                    + early_data*
                                                       {Finished}
                       <---------------------- [Application Data]
  (EndOfEarlyData)
  {Finished}           ---------------------->

  [Application Data]   <---------------------> [Application Data]

  +  Indicates noteworthy extensions sent in the
     previously noted message.
  *  Indicates optional or situation-dependent
     messages/extensions that are not always sent.
  () encrypted with Client->Hidden 0-RTT key
  {} encrypted with Client->Hidden 1-RTT handshake
  [] encrypted with Client->Hidden 1-RTT key
~~~

The Fronting server that receives the Client Hello will find
the combined ticket in the pre_shared_key extensions, just as it would in
a regular session resumption attempt. When parsing the ticket, the
Fronting server will discover that the session really is meant to be resumed
with the Hidden server. It will arrange for all the connection data
to be forwarded to the Hidden server, including forwarding a copy of
the initial Client Hello.

The Hidden server will receive the Client Hello. It will obtain the
identity of the Fronting service from the SNI parameter. It will then parse
the session resumption ticket, and proceed with the resumption of
the session. 

In this design, the Client Hello message is relayed unchanged from Fronting
server to hidden server. This ensures that code changes are confined to
the interpretation of the message parameters. The construction of
handshake contexts is left unchanged. 

## New Combined Session Ticket {#newcomboticket}

In normal TLS 1.3 operations, the server can send New Session Ticket
messages at any time after the receiving the Client Finished message.
The ticket structure is defined in TLS 1.3 as:


       struct {
           uint32 ticket_lifetime;
           uint32 ticket_age_add;
           opaque ticket_nonce<1..255>;
           opaque ticket<1..2^16-1>;
           Extension extensions<0..2^16-2>;
       } NewSessionTicket;

When SNI encryption is enabled, tickets will carry a "Fronting SNI"
extension, and the ticket value itself will be negotiated between 
Fronting Service and Hidden Service, as in:

~~~
Client                    Fronting Service         Hidden Service

                                      <=======   <Ticket Request>
                      Combined Ticket =======>
                                              [New Session Ticket
                     <------------------------    + SNI Extension]

  <==> sent on connection between Hidden and Fronting service   
  <>   encrypted with Fronting<->Hidden key
  [] encrypted with Client->Hidden 1-RTT key
~~~

In theory, the actual format of the ticket could be set by mutual agreement
between Fronting Service and Hidden Service. In practice, it is probably better
to provide guidance, as the ticket must meet three requirements:

* The Fronting Server must understand enough of the combined ticket
  to relay the connection towards the Hidden Server;

* The Hidden Server must understand enough of the combined ticket to
  resume the session with the client;

* Third parties must not be able to deduce the name of the Hidden
  Service from the value of the ticket.

There are three plausible designs, a stateful design, a shared key design,
and a 

In the stateful design, the ticket are just random numbers that the
Fronting server associates with the Hidden server, and the Hidden server
associates with the session context. The shared key design would
work as follow:

  * the hidden server and the fronting server share a symmetric key
    K_sni.

  * the "clear text" ticket includes a nonce, the ordinary ticket used for session
    resumption by the hidden service, and the id of the Hidden service
    for the Fronting Service.

  * the ticket will be encrypted with AEAD, using the nonce as an IV.

  * When the client reconnects to the fronting server, it decrypts
    the ticket using K_sni and if it succeeds, then it just forwards
    the Client Hello to the hidden server indicated in id-hidden-service
    (which of course has to know to ignore SNI).
    Otherwise, it terminates the connection itself with its own
    SNI.

The hidden server can just refresh the ticket any time it pleases, as usual.

This design allows the Hidden Service to hide behind many Fronting Services,
each using a different key. The Client Hello received by the Hidden Server
carries the SNI of the Fronting Service, which the Hidden Server can use to
select the appropriate K_sni.

In the public key design, the Hidden Server encrypts the tickets with
a public key of the Fronting Server. The ticket itself would be similar
to what is used in the shared key design. The compute cost for a single
decryption may be higher, but the Fronting Server would not need to 
blindly try multiple decryption keys associated with multiple Hidden Servers.
The Hidden Server would not be able to decrypt the ession Tickets, which means
that it would have to rely on some kind of stateful storage.

## First session {#newfirstsession}

The previous sections present how sessions can be resumed with the combined
ticket. Clients have that have never contacted the Hidden Server will need
to obtain a first ticket during a first session.
The most plausible option is to have the client directly connect
to the Hidden Service, and then ask for a combined ticket. The obvious
issue is that the SNI will not be encrypted for this first connection,
which exposes the client to surveillance and censorship.

The client may also learn about the relation between Fronting Service and
Hidden Service through an out of band channel, such as DNS service, or
word of mouth. However, it is difficult to establish a combined ticket
completely out of band, since the ticket must be associated to two
shared secrets, one understood by the Fronting service and the other 
shared with the Hidden service to ensure protection against replay attacks.

An alternative may be to use the TLS-in-TLS service described in
(#tlsintls) for the first contact.
There will be some overhead due to tunnelling, but as we discussed
in (#tlsintlsclientreq) the tunneling solution allows for
safe first contact. Yet another way would be to use the HTTPS in
HTTPS tunneling described in (#httpfrontingtunnels).

# Security Considerations {#secusec}

The encapsulation protocol proposed in this draft mitigates the known attacks
listed in [@!I-D.ietf-tls-sni-encryption]. For example, the encapsulation design uses pairwise
security contexts, and is not dependent on the widely shared secrets described
in (#sharedsecrets). The design also does not rely on additional public key
operations by the multiplexed server or by the fronting server, and thus does
not open the attack surface for  denial of service discussed in (#serveroverload).
The session keys are negotiated end to end between the client and the
protected service, as required in (#nocontextsharing).

The combined ticket solution also mitigates the known attacks. 
The design also uses pairwise
security contexts, and is not dependent on the widely shared secrets described
in (#sharedsecrets). The design also does not rely on additional public key
operations by the multiplexed server or by the fronting server, and thus does
not open the attack surface for  denial of service discussed in (#serveroverload).
The session keys are negotiated end to end between the client and the
protected service, as required in (#nocontextsharing).

However, in some cases, proper mitigation depends on careful implementation.

## Replay attacks and side channels {#sidechannels}

Both solutions mitigate the replay attacks described in (#replayattack)
because adversaries cannot decrypt the replies intended
for the client. However, the connection from the
fronting service to the hidden service can be observed through
side channels.

To give an obvious example, suppose that
the fronting service merely relays the data
by establishing a TCP connection to the hidden service.
An adversary capable of observing all
network traffic at the fronting server
can associate the arrival of an encrypted message to the fronting
service and the TCP handshake between the
fronting server and the hidden service, and deduce
which hidden service the user accessed.

The mitigation of this attack relies on proper implementation
of the fronting service. This may require cooperation from the multiplexed
server.

## Sticking out

The TLS encapsulation protocol mostly fulfills the requirements to "not
stick out" expressed in (#snireqdontstickout).
The initial messages will be sent as 0-RTT data, and will be encrypted using
the 0-RTT key negotiated with the fronting service. Adversaries cannot
tell whether the client is using TLS encapsulation or some other
0-RTT service. However, this is only true if the fronting service
regularly uses 0-RTT data.

The combined token solution almost perfectly fulfills the requirements to "not
stick out" expressed in (#snireqdontstickout), as the observable flow of
message is almost exactly the same as a regular TLS connection. However,
adversaries could observe the values of the PSK Identifier that contains
the combined ticket. The proposed ticket structure is designed to thwart
analysis of the ticket, but if implementations are not careful the size of
the combined ticket can be used as a side channel allowing adversaries to
distinguish between different Hidden Services located behind the same
Fronting Service.

## Forward Secrecy

In the TLS encapsulation protocol, the encapsulated Client Hello is encrypted
using the session resumption key. If this key is revealed, the Client Hello data
will also be revealed. The mitigation there is to not use the same session resumption
key multiple time.

The most common implementations of TLS tickets have the server using Session Ticket
Encryption Keys (STEKs) to create an encrypted copy of the session parameters
which is then stored by the client. When the client resumes, it supplies this
encrypted copy, the server decrypts it, and has the parameters it needs to resume.
The server need only remember the STEK. If a STEK is disclosed to an adversary, then all
of the data encrypted by sessions protected by the STEK may be decrypted by an adversary.

To mitigate this attack, server implementations of the combined ticket protocol
SHOULD use stateful tickets instead of STEK protected TLS tickets. If they do
rely on STEK protected tickets, they MUST ensure that the K_sni keys used to
encrypt these tickets are rotated frequently.

# IANA Considerations

Do we need to register an extension point? Or is it just OK to
use early data?

# Acknowledgements

A large part of this draft originates in discussion of SNI encryption
on the TLS WG mailing list, including comments after the tunneling
approach was first proposed in a message to that list:
https://mailarchive.ietf.org/arch/msg/tls/tXvdcqnogZgqmdfCugrV8M90Ftw.

During the discussion of SNI Encryption in Yokohama, Deb Cooley
argued that rather than messing with TLS to allow SNI encryption,
we should just tunnel TLS in TLS. A number of people objected
to this on the grounds of the performance cost for the Fronting Server
because it has to encrypt and decrypt everything.

After the meeting, Martin Thomson suggested a modification to the
tunnelling proposal that removes this cost. The key observation is
that if we think of the 0-RTT flight as a separate message attached to
the handshake, then we can tunnel a second first flight in it.

The combined ticket approach was first proposed by Cedric Fournet and
Antoine Delignaut-Lavaud.

The delegation token design comes from many people, including
Ben Schwartz, Brian Sniffen and Rich Salz.

Thanks to Daniel Kahn Gillmor for a pretty detailed review of the 
initial draft.

{backmatter}