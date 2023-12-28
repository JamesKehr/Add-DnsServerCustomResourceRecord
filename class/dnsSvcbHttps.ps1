<#

    ### RESEARCH AND NOTES ###

    This class manages adding SeRviCe Binding (SVCB) records.

    SVCB records are used to inform clients what ALPN (Application-Layer Protocol Negotiation) the service uses. This is used primarily by web servers to advertise the version of HTTP, IP address hints, and alternate ports.


    Query a SVCB record with dig

    dig cloudflare.com -t type65 @1.1.1.1

    Dig for Windows is no longer supported. Use WSL2 to get access to dig.

    Sample SVCB from Wireshark.

    Frame 2: 158 bytes on wire (1264 bits), 158 bytes captured (1264 bits) on interface \Device\NPF_{1D66F33A-F88C-473C-AD32-A42918977B0E}, id 1
    Ethernet II, Src: Ubiquiti_3c:19:13 (24:a4:3c:3c:19:13), Dst: ASUSTekCOMPU_b4:34:9e (4c:ed:fb:b4:34:9e)
    Internet Protocol Version 4, Src: 1.1.1.1, Dst: 192.168.3.101
    User Datagram Protocol, Src Port: 53, Dst Port: 60259
    Domain Name System (response)
        Transaction ID: 0x8bbc
        Flags: 0x81a0 Standard query response, No error
        Questions: 1
        Answer RRs: 1
        Authority RRs: 0
        Additional RRs: 1
        Queries
            cloudflare.com: type HTTPS, class IN
                Name: cloudflare.com
                [Name Length: 14]
                [Label Count: 2]
                Type: HTTPS (65) (HTTPS Specific Service Endpoints)
                Class: IN (0x0001)
        Answers
            cloudflare.com: type HTTPS, class IN
                Name: cloudflare.com
                Type: HTTPS (65) (HTTPS Specific Service Endpoints)
                Class: IN (0x0001)
                Time to live: 43 (43 seconds)
                Data length: 61
                SvcPriority: 1
                TargetName: <Root>
                SvcParam: alpn=h3,h2
                    SvcParamKey: alpn (1)
                    SvcParamValue length: 6
                    ALPN length: 2
                    ALPN: h3
                    ALPN length: 2
                    ALPN: h2
                SvcParam: ipv4hint=104.16.132.229,104.16.133.229
                    SvcParamKey: ipv4hint (4)
                    SvcParamValue length: 8
                    IP: 104.16.132.229
                    IP: 104.16.133.229
                SvcParam: ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
                    SvcParamKey: ipv6hint (6)
                    SvcParamValue length: 32
                    IP: 2606:4700::6810:84e5
                    IP: 2606:4700::6810:85e5
        Additional records
            <Root>: type OPT
                Name: <Root>
                Type: OPT (41) 
                UDP payload size: 1232
                Higher bits in extended RCODE: 0x00
                EDNS0 version: 0
                Z: 0x0000
                    0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                    .000 0000 0000 0000 = Reserved: 0x0000
                Data length: 0
        [Request In: 1]
        [Time: 0.009658000 seconds]


    Hex dump of just the DNS data:

    0000   8b bc 81 a0 00 01 00 01 00 00 00 01 0a 63 6c 6f
    0010   75 64 66 6c 61 72 65 03 63 6f 6d 00 00 41 00 01
    0020   c0 0c 00 41 00 01 00 00 00 2b 00 3d 00 01 00 00
    0030   01 00 06 02 68 33 02 68 32 00 04 00 08 68 10 84
    0040   e5 68 10 85 e5 00 06 00 20 26 06 47 00 00 00 00
    0050   00 00 00 00 00 68 10 84 e5 26 06 47 00 00 00 00
    0060   00 00 00 00 00 68 10 85 e5 00 00 29 04 d0 00 00
    0070   00 00 00 00

    0000   8b bc 81 a0 00 01 00 01 00 00 00 01 0a 63 6c 6f   .............clo
    0010   75 64 66 6c 61 72 65 03 63 6f 6d 00 00 41 00 01   udflare.com..A..
    0020   c0 0c 00 41 00 01 00 00 00 2b 00 3d 00 01 00 00   ...A.....+.=....
    0030   01 00 06 02 68 33 02 68 32 00 04 00 08 68 10 84   ....h3.h2....h..
    0040   e5 68 10 85 e5 00 06 00 20 26 06 47 00 00 00 00   .h...... &.G....
    0050   00 00 00 00 00 68 10 84 e5 26 06 47 00 00 00 00   .....h...&.G....
    0060   00 00 00 00 00 68 10 85 e5 00 00 29 04 d0 00 00   .....h.....)....
    0070   00 00 00 00                                       ....

    Hex stream of just the answer:

    0001000001000602683302683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5

    Individual components of the answer:

    [Do not include in record data hex stream. This is always the record name.]
    Name: cloudflare.com
    0000   c0 0c                                             ..

    [Not in record data hex stream. This is owned by the DNS server.]
    Type: HTTPS (65) (HTTPS Specific Service Endpoints)
    0000   00 41                                             .A

    [Not in record data hex stream.]
    Class: IN (0x0001)
    0000   00 01                                             ..

    [Not in record data hex stream.]
    Time to live: 43 (43 seconds)
    0000   00 00 00 2b                                       ...+

    [Not in record data hex stream. This is owned by the DNS server.]
    Data length: 61
    0000   00 3d                                             .=

    [Start record data hex stream here!]
    SvcPriority: 1
    0000   00 01                                             ..

    [In recrod data hex stream.]
    TargetName: <Root>
    0000   00                                                .

    [In recrod data hex stream.]
    SvcParam: alpn=h3,h2
        SvcParamKey: alpn (1)
        0000   00 01                                             ..

        SvcParamValue length: 6
        0000   00 06                                             ..

        ALPN length: 2
        0000   02                                                .

        ALPN: h3
        0000   68 33                                             h3

        ALPN length: 2
        0000   02                                                .

        ALPN: h2
        0000   68 32                                             h2

    [In recrod data hex stream.]
    SvcParam: ipv4hint=104.16.132.229,104.16.133.229
        SvcParamKey: ipv4hint (4)
        0000   00 04                                             ..

        SvcParamValue length: 8
        0000   00 08                                             ..

        IP: 104.16.132.229
        0000   68 10 84 e5                                       h...

        IP: 104.16.133.229
        0000   68 10 85 e5                                       h...
    
    [In recrod data hex stream.]
    SvcParam: ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
        SvcParamKey: ipv6hint (6)
        0000   00 06                                             ..

        SvcParamValue length: 32
        0000   00 20                                             . 

        IP: 2606:4700::6810:84e5
        0000   26 06 47 00 00 00 00 00 00 00 00 00 68 10 84 e5   &.G.........h...

        IP: 2606:4700::6810:85e5
        0000   26 06 47 00 00 00 00 00 00 00 00 00 68 10 85 e5   &.G.........h...


      Sample command:

      Add-DnsServerResourceRecord -Type 65 -RecordData "0001000001000602683302683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5" -ZoneName kehr.home -Name test

      Result:

      Answers
        test.kehr.home: type HTTPS, class IN
            Name: test.kehr.home
            Type: HTTPS (65) (HTTPS Specific Service Endpoints)
            Class: IN (0x0001)
            Time to live: 3600 (1 hour)
            Data length: 61
            SvcPriority: 1
            TargetName: <Root>
            SvcParam: alpn=h3,h2
                SvcParamKey: alpn (1)
                SvcParamValue length: 6
                ALPN length: 2
                ALPN: h3
                ALPN length: 2
                ALPN: h2
            SvcParam: ipv4hint=104.16.132.229,104.16.133.229
                SvcParamKey: ipv4hint (4)
                SvcParamValue length: 8
                IP: 104.16.132.229
                IP: 104.16.133.229
            SvcParam: ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
                SvcParamKey: ipv6hint (6)
                SvcParamValue length: 32
                IP: 2606:4700::6810:84e5
                IP: 2606:4700::6810:85e5


    The SVCB RR has two modes: 
    1) "AliasMode", which simply delegates operational control for a resource and 
    2) "ServiceMode", which binds together configuration information for a service endpoint. ServiceMode provides additional key=value parameters within each RDATA set.

    SvcPriority (Section 2.4.1):
    The priority of this record (relative to others, with lower values preferred). A value of 0 indicates AliasMode.

    AliasMode (SvcPriority 0):

    https://www.rfc-editor.org/rfc/rfc9460#name-aliasmode

    Summary - It acts as a CNAME for the zone apex, without the security risk. The AliasMode record points to a record but does not redirect the domain itself. Just a service for the domain.

    "In AliasMode, the SVCB record aliases a service to a TargetName. SVCB RRsets SHOULD only have a single RR in AliasMode. If multiple AliasMode RRs are present, clients or recursive resolvers SHOULD pick one at random."


    ServiceMode (SvcPriority 1):

    https://www.rfc-editor.org/rfc/rfc9460#name-servicemode

    Summary - Provides service endpoint details, such as protocol (h2 (http/2), h2 (http/3)), alternate port, and IPv4/v6 address hints.

    "In ServiceMode, the TargetName and SvcParams within each RR associate an alternative endpoint for the service with its connection parameters."

    ServiceMode has, as of RFC 9460, four SvcParamKeys: Application-Layer Protocol Negotiation (ALPN), port, ipv4/ipv6 hint, mandatory. Keys MUST be in numerical order, based on the key number. This order is, as of RPC 9460:

    https://www.rfc-editor.org/rfc/rfc9460#name-initial-contents

    The "Service Parameter Keys (SvcParamKeys)" registry has been populated with the following initial registrations:

    Table 1
    Number	    Name	            Meaning	                                  Reference	            Change Controller
    0	          mandatory	        Mandatory keys in this RR	                RFC 9460, Section 8	  IETF
    1	          alpn	            Additional supported protocols	          RFC 9460, Section 7.1	IETF
    2	          no-default-alpn	  No support for default protocol	          RFC 9460, Section 7.1	IETF
    3	          port	            Port for alternative endpoint	            RFC 9460, Section 7.2	IETF
    4	          ipv4hint	        IPv4 address hints	                      RFC 9460, Section 7.3	IETF
    5	          ech	              RESERVED (held for Encrypted ClientHello) N/A	                  IETF
    6	          ipv6hint	        IPv6 address hints	                      RFC 9460, Section 7.3	IETF
    65280-65534 N/A	              Reserved for Private Use	                RFC 9460	            IETF
    65535	      N/A	              Reserved ("Invalid key")	                RFC 9460	            IETF

    In addition to SvcParamKeys, encryption keys can be added to the ServiceMode. "Enabling the conveyance of Encrypted ClientHello keys [ECH] associated with an alternative endpoint."

    
    When the TargetName is "." ...
    
      AliasMode - "...indicates that the service is not available or does not exist. This indication is advisory: clients encountering this indication MAY ignore it and attempt to connect without the use of SVCB"

      ServiceMode = "... the owner name of this record MUST be used as the effective TargetName." i.e. if the record name is "svc" and the zone is "example.net", the effectice TargetName is svc.example.net.
    
    Details: https://www.rfc-editor.org/rfc/rfc9460#name-special-handling-of-in-targ

    In this example, from the RFC, an AliasMode record redirects a web service at "example.com." to "svc.example.net.".
        
        example.com.      7200  IN HTTPS 0 svc.example.net.
    
    A CNAME then redirects svc to svc2.

      svc.example.net.  7200  IN CNAME svc2.example.net.
    
    A SVCB record for svc2 sets an alternate port for the web service, at port 8002.

      svc2.example.net. 7200  IN HTTPS 1 . port=8002

    Standard A and AAAA records provide the addresses of svc2.

      svc2.example.net. 300   IN A     192.0.2.2
      svc2.example.net. 300   IN AAAA  2001:db8::2


    What this class needs to handle:

      - SvcPriority: 0 for AliasMode, 1 for ServiceMode. The class must maintain the proper mode (i.e. SvcParams cannot be addes to AliasMode records)
      - TargetName: [ServiceMode] "." for effective record, anything else to set an alternate TargetName. [AliasMode] "." for ignore, anything else to set an alias. One alias per record, but multiple AliasMode records are allowed.
      - SvcParam: 


#>


using namespace System.Collections
using namespace System.Collections.Generic

### ALPN ###
#region
<#
# https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
$alpnCsvUrl = "https://www.iana.org/assignments/tls-extensiontype-values/alpn-protocol-ids.csv"

# get the ALPN CSV
$alpnCsvRaw = Invoke-WebRequest $alpnCsvUrl -UseBasicParsing | ForEach-Object Content | ConvertFrom-Csv | Where-Object {$_.Protocol -ne "Reserved" }

# process the CSV file
$alpnObj = [List[Object]]::new()

foreach ( $alpn in $alpnCsvRaw ) {
    $protocol = $alpn.Protocol
    $idSeq = $alpn.'Identification Sequence'

    # create the RFC URL if needed
    try {
        if ($alpn.Reference -match "http") {
            $rfc = $alpn.Reference.Trim('[').Trim(']')
            $rfcURLtmp = [System.Uri]::new($rfc)
            $rfcURL = $rfcURLtmp.AbsoluteUri.ToString()
        } elseif ($alpn.Reference -match "RFC") {
            $rfc = $alpn.Reference.Trim('[').Trim(']')
            $rfcURLtmp = [System.Uri]::new("https://datatracker.ietf.org/doc/html/$rfc")
            $rfcURL = $rfcURLtmp.AbsoluteUri.ToString()
        } else {
            $rfcURL = $alpn.Reference
        }
    }
    catch {
        # here there be errors
        $rfcURL = $rfc
    }
    
    # split $idSeq into hex and string
    $idSeqHex = $idSeq.Split('(')[0]
    $idSeqStr = $idSeq.Split('(')[1].Trim('")“”')

    $tmpObj = [PSCustomObject]@{
        Protocol = $protocol
        alpnStr  = $idSeqStr
        alpnHex  = $idSeqHex
        ProtURL  = $rfcURL
    }

    $alpnObj.Add($tmpObj)

    Remove-Variable protocol,idSeq,rfc,rfcURL,idSeqHex,idSeqStr,tmpObj -EA SilentlyContinue
}

$alpn | Add-Member -MemberType NoteProperty -Name alpnEnum -Value ""
$alpn | Add-Member -MemberType NoteProperty -Name alpnHexStream -Value ""


$alpn | foreach {
  $tmpEnum = $_.alpnStr -replace "[\-|\.|\\|\/]",'_'
  $_.alpnEnum = $tmpEnum

  $tmpHexStream = $_.alpnHex.TrimStart('0x') -replace ' 0x', ''
  $_.alpnHexStream = $tmpHexStream.Trim(' ')
}

$ianaALPN | Add-Member -MemberType NoteProperty -Name alpnLength -Value 0
$ianaALPN | foreach {
  $len = $_.alpnHex.Trim(" ").Split(' ').Count
  $_.alpnLength = $len

  $_.alpnHex = $_.alpnHex.Trim(' ')
}

# generate the class content --- manual editing of URLs is required
$ianaALPN | Select-Object Protocol, alpnStr, alpnEnum, alpnHex, alpnLength, alpnHexStream, ProtURL | ConvertTo-Json | Out-String

#>

# generate the ALPN data
$alpnJSON = @'
[
  {
    "Protocol": "HTTP/0.9",
    "alpnStr": "http/0.9",
    "alpnEnum": "http_0_9",
    "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x30 0x2e 0x39",
    "alpnLength": 8,
    "alpnHexStream": "687474702f302e39",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1945"
  },
  {
    "Protocol": "HTTP/1.0",
    "alpnStr": "http/1.0",
    "alpnEnum": "http_1_0",
    "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x30",
    "alpnLength": 8,
    "alpnHexStream": "687474702f312e30",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1945"
  },
  {
    "Protocol": "HTTP/1.1",
    "alpnStr": "http/1.1",
    "alpnEnum": "http_1_1",
    "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x31",
    "alpnLength": 8,
    "alpnHexStream": "687474702f312e31",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9112"
  },
  {
    "Protocol": "SPDY/1",
    "alpnStr": "spdy/1",
    "alpnEnum": "spdy_1",
    "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x31",
    "alpnLength": 6,
    "alpnHexStream": "737064792f31",
    "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1"
  },
  {
    "Protocol": "SPDY/2",
    "alpnStr": "spdy/2",
    "alpnEnum": "spdy_2",
    "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x32",
    "alpnLength": 6,
    "alpnHexStream": "737064792f32",
    "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2"
  },
  {
    "Protocol": "SPDY/3",
    "alpnStr": "spdy/3",
    "alpnEnum": "spdy_3",
    "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x33",
    "alpnLength": 6,
    "alpnHexStream": "737064792f33",
    "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3"
  },
  {
    "Protocol": "Traversal Using Relays around NAT (TURN)",
    "alpnStr": "stun.turn",
    "alpnEnum": "stun_turn",
    "alpnHex": "0x73 0x74 0x75 0x6E 0x2E 0x74 0x75 0x72 0x6E",
    "alpnLength": 9,
    "alpnHexStream": "7374756E2E7475726E",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7443"
  },
  {
    "Protocol": "NAT discovery using Session Traversal Utilities for NAT (STUN)",
    "alpnStr": "stun.nat-discovery",
    "alpnEnum": "stun_nat_discovery",
    "alpnHex": "0x73 0x74 0x75 0x6E 0x2E 0x6e 0x61 0x74 0x2d 0x64 0x69 0x73 0x63 0x6f 0x76 0x65 0x72 0x79",
    "alpnLength": 18,
    "alpnHexStream": "7374756E2E6e61742d646973636f76657279",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7443"
  },
  {
    "Protocol": "HTTP/2 over TLS",
    "alpnStr": "h2",
    "alpnEnum": "h2",
    "alpnHex": "0x68 0x32",
    "alpnLength": 2,
    "alpnHexStream": "6832",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9113"
  },
  {
    "Protocol": "HTTP/2 over TCP",
    "alpnStr": "h2c",
    "alpnEnum": "h2c",
    "alpnHex": "0x68 0x32 0x63",
    "alpnLength": 3,
    "alpnHexStream": "683263",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9113"
  },
  {
    "Protocol": "WebRTC Media and Data",
    "alpnStr": "webrtc",
    "alpnEnum": "webrtc",
    "alpnHex": "0x77 0x65 0x62 0x72 0x74 0x63",
    "alpnLength": 6,
    "alpnHexStream": "776562727463",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8833"
  },
  {
    "Protocol": "Confidential WebRTC Media and Data",
    "alpnStr": "c-webrtc",
    "alpnEnum": "c_webrtc",
    "alpnHex": "0x63 0x2d 0x77 0x65 0x62 0x72 0x74 0x63",
    "alpnLength": 8,
    "alpnHexStream": "632d776562727463",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8833"
  },
  {
    "Protocol": "FTP",
    "alpnStr": "ftp",
    "alpnEnum": "ftp",
    "alpnHex": "0x66 0x74 0x70",
    "alpnLength": 3,
    "alpnHexStream": "667470",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC959"
  },
  {
    "Protocol": "IMAP",
    "alpnStr": "imap",
    "alpnEnum": "imap",
    "alpnHex": "0x69 0x6d 0x61 0x70",
    "alpnLength": 4,
    "alpnHexStream": "696d6170",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC2595"
  },
  {
    "Protocol": "POP3",
    "alpnStr": "pop3",
    "alpnEnum": "pop3",
    "alpnHex": "0x70 0x6f 0x70 0x33",
    "alpnLength": 4,
    "alpnHexStream": "706f7033",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC2595"
  },
  {
    "Protocol": "ManageSieve",
    "alpnStr": "managesieve",
    "alpnEnum": "managesieve",
    "alpnHex": "0x6d 0x61 0x6e 0x61 0x67 0x65 0x73 0x69 0x65 0x76 0x65",
    "alpnLength": 11,
    "alpnHexStream": "6d616e6167657369657665",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC5804"
  },
  {
    "Protocol": "CoAP",
    "alpnStr": "coap",
    "alpnEnum": "coap",
    "alpnHex": "0x63 0x6f 0x61 0x70",
    "alpnLength": 4,
    "alpnHexStream": "636f6170",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8323"
  },
  {
    "Protocol": "XMPP jabber:client namespace",
    "alpnStr": "xmpp-client",
    "alpnEnum": "xmpp_client",
    "alpnHex": "0x78 0x6d 0x70 0x70 0x2d 0x63 0x6c 0x69 0x65 0x6e 0x74",
    "alpnLength": 11,
    "alpnHexStream": "786d70702d636c69656e74",
    "ProtURL": "https://xmpp.org/extensions/xep-0368.html"
  },
  {
    "Protocol": "XMPP jabber:server namespace",
    "alpnStr": "xmpp-server",
    "alpnEnum": "xmpp_server",
    "alpnHex": "0x78 0x6d 0x70 0x70 0x2d 0x73 0x65 0x72 0x76 0x65 0x72",
    "alpnLength": 11,
    "alpnHexStream": "786d70702d736572766572",
    "ProtURL": "https://xmpp.org/extensions/xep-0368.html"
  },
  {
    "Protocol": "acme-tls/1",
    "alpnStr": "acme-tls/1",
    "alpnEnum": "acme_tls_1",
    "alpnHex": "0x61 0x63 0x6d 0x65 0x2d 0x74 0x6c 0x73 0x2f 0x31",
    "alpnLength": 10,
    "alpnHexStream": "61636d652d746c732f31",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8737"
  },
  {
    "Protocol": "OASIS Message Queuing Telemetry Transport (MQTT)",
    "alpnStr": "mqtt",
    "alpnEnum": "mqtt",
    "alpnHex": "0x6d 0x71 0x74 0x74",
    "alpnLength": 4,
    "alpnHexStream": "6d717474",
    "ProtURL": "http://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html"
  },
  {
    "Protocol": "DNS-over-TLS",
    "alpnStr": "dot",
    "alpnEnum": "dot",
    "alpnHex": "0x64 0x6F 0x74",
    "alpnLength": 3,
    "alpnHexStream": "646F74",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7858"
  },
  {
    "Protocol": "Network Time Security Key Establishment, version 1",
    "alpnStr": "ntske/1",
    "alpnEnum": "ntske_1",
    "alpnHex": "0x6E 0x74 0x73 0x6B 0x65 0x2F 0x31",
    "alpnLength": 7,
    "alpnHexStream": "6E74736B652F31",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8915"
  },
  {
    "Protocol": "SunRPC",
    "alpnStr": "sunrpc",
    "alpnEnum": "sunrpc",
    "alpnHex": "0x73 0x75 0x6e 0x72 0x70 0x63",
    "alpnLength": 6,
    "alpnHexStream": "73756e727063",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9289"
  },
  {
    "Protocol": "HTTP/3",
    "alpnStr": "h3",
    "alpnEnum": "h3",
    "alpnHex": "0x68 0x33",
    "alpnLength": 2,
    "alpnHexStream": "6833",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9114"
  },
  {
    "Protocol": "SMB2",
    "alpnStr": "smb",
    "alpnEnum": "smb",
    "alpnHex": "0x73 0x6D 0x62",
    "alpnLength": 3,
    "alpnHexStream": "736D62",
    "ProtURL": "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962"
  },
  {
    "Protocol": "IRC",
    "alpnStr": "irc",
    "alpnEnum": "irc",
    "alpnHex": "0x69 0x72 0x63",
    "alpnLength": 3,
    "alpnHexStream": "697263",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1459"
  },
  {
    "Protocol": "NNTP",
    "alpnStr": "nntp",
    "alpnEnum": "nntp",
    "alpnHex": "0x6E 0x6E 0x74 0x70",
    "alpnLength": 4,
    "alpnHexStream": "6E6E7470",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC3977"
  },
  {
    "Protocol": "DoQ",
    "alpnStr": "doq",
    "alpnEnum": "doq",
    "alpnHex": "0x64 0x6F 0x71",
    "alpnLength": 3,
    "alpnHexStream": "646F71",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9250"
  },
  {
    "Protocol": "SIP",
    "alpnStr": "sip/2",
    "alpnEnum": "sip_2",
    "alpnHex": "0x73 0x69 0x70 0x2f 0x32",
    "alpnLength": 5,
    "alpnHexStream": "7369702f32",
    "ProtURL": "https://datatracker.ietf.org/doc/html/RFC3261"
  },
  {
    "Protocol": "TDS/8.0",
    "alpnStr": "tds/8.0",
    "alpnEnum": "tds_8_0",
    "alpnHex": "0x74 0x64 0x73 0x2f 0x38 0x2e 0x30",
    "alpnLength": 7,
    "alpnHexStream": "7464732f382e30",
    "ProtURL": "[[MS-TDS]: Tabular Data Stream Protocol]"
  },
  {
    "Protocol": "DICOM",
    "alpnStr": "dicom",
    "alpnEnum": "dicom",
    "alpnHex": "0x64 0x69 0x63 0x6f 0x6d",
    "alpnLength": 5,
    "alpnHexStream": "6469636f6d",
    "ProtURL": "https://www.dicomstandard.org/current"
  }
]
'@

$script:ianaALPN = $alpnJSON | ConvertFrom-Json

#endregion

### ENUM ###
#region
<#

$formALPNStr = $ALPN.alpnStr -replace "[\-|\.|\\|\/]",'_'

@"
enum DnsSvcbHttpsAlpn {
$($formALPNStr | Foreach-Object { "   $_`n" })
}
"@

#>


<#
  https://www.rfc-editor.org/rfc/rfc9460#section-7.1

  7.1. "alpn" and "no-default-alpn"
  
  The "alpn" and "no-default-alpn" SvcParamKeys together indicate the set of Application-Layer Protocol Negotiation (ALPN) 
  protocol identifiers [ALPN] and associated transport protocols supported by this service endpoint (the "SVCB ALPN set").

  As with Alt-Svc [AltSvc], each ALPN protocol identifier is used to identify the application protocol and associated suite 
  of protocols supported by the endpoint (the "protocol suite"). The presence of an ALPN protocol identifier in the SVCB ALPN 
  set indicates that this service endpoint, described by TargetName and the other parameters (e.g., "port"), offers service 
  with the protocol suite associated with this ALPN identifier.

  Clients filter the set of ALPN identifiers to match the protocol suites they support, and this informs the underlying 
  transport protocol used (such as QUIC over UDP or TLS over TCP). ALPN protocol identifiers that do not uniquely identify a 
  protocol suite (e.g., an Identification Sequence that can be used with both TLS and DTLS) are not compatible with this 
  SvcParamKey and MUST NOT be included in the SVCB ALPN set.


#>

enum DnsSvcbHttpsAlpn {
   http_0_9
   http_1_0
   http_1_1
   spdy_1
   spdy_2
   spdy_3
   stun_turn
   stun_nat_discovery
   h2
   h2c
   webrtc
   c_webrtc
   ftp
   imap
   pop3
   managesieve
   coap
   xmpp_client
   xmpp_server
   acme_tls_1
   mqtt
   dot
   ntske_1
   sunrpc
   h3
   smb
   irc
   nntp
   doq
   sip_2
   tds_8_0
   dicom
}

enum DnsSvcbHttpsPriority {
  AliasMode
  ServiceMode
}

enum DnsSvcbHttpsMandatoryKeyName {
  alpn
  noalpn
  port
  ipv4hint
  ipv6hint
}

[hashtable]$script:DnsSvcbHttpsMandatoryKeyValue = @{
  alpn     = 1
  noalpn   = 2
  port     = 3
  ipv4hint = 4
  ipv6hint = 6
}

$DnsSvcbHttpsSvcParamKeysJSON = @'
[
  {
    "Number": 0,
    "Name": "mandatory",
    "enumName": "mandatory",
    "Meaning": "Mandatory keys in this RR",
    "HexStream": "0000"
  },
  {
    "Number": 1,
    "Name": "alpn",
    "enumName": "alpn",
    "Meaning": "Additional supported protocols",
    "HexStream": "0001"
  },
  {
    "Number": 2,
    "Name": "no-default-alpn",
    "enumName": "noalpn",
    "Meaning": "No support for default protocol",
    "HexStream": "0002"
  },
  {
    "Number": 3,
    "Name": "port",
    "enumName": "port",
    "Meaning": "Port for alternative endpoint",
    "HexStream": "0003"
  },
  {
    "Number": 4,
    "Name": "ipv4hint",
    "enumName": "ipv4hint",
    "Meaning": "IPv4 address hints",
    "HexStream": "0004"
  },
  {
    "Number": 6,
    "Name": "ipv6hint",
    "enumName": "ipv6hint",
    "Meaning": "IPv6 address hints",
    "HexStream": "0006"
  }
]
'@

$script:DnsSvcbHttpsSvcParamKeys = $DnsSvcbHttpsSvcParamKeysJSON | ConvertFrom-Json

#endregion

<#

https://www.rfc-editor.org/rfc/rfc9460#name-initial-contents

The "Service Parameter Keys (SvcParamKeys)" registry has been populated with the following initial registrations:

Table 1
Number	    Name	            Meaning	                                  Reference	            Change Controller
0	          mandatory	        Mandatory keys in this RR	                RFC 9460, Section 8	  IETF
1	          alpn	            Additional supported protocols	          RFC 9460, Section 7.1	IETF
2	          no-default-alpn	  No support for default protocol	          RFC 9460, Section 7.1	IETF
3	          port	            Port for alternative endpoint	            RFC 9460, Section 7.2	IETF
4	          ipv4hint	        IPv4 address hints	                      RFC 9460, Section 7.3	IETF
5	          ech	              RESERVED (held for Encrypted ClientHello) N/A	                  IETF
6	          ipv6hint	        IPv6 address hints	                      RFC 9460, Section 7.3	IETF
65280-65534 N/A	              Reserved for Private Use	                RFC 9460	            IETF
65535	      N/A	              Reserved ("Invalid key")	                RFC 9460	            IETF


Initally supported SvcParams keys are: 0, 1, 2, 4, 6


Encrypted Client Hello (ECH) is still in draft. ECH and custom keys for ECH will not be supported until it is approved 
and a real world example can be analyzed. This will most likely come from CloudFlare or Fastly, based on the RFC.

https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17
#>

<#
https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml


Number      Name 	          Meaning 	                                                Change Controller 	Reference 
0	          mandatory	      Mandatory keys in this RR	                                IETF	              [RFC9460, Section 8]
1	          alpn	          Additional supported protocols	                          IETF	              [RFC9460, Section 7.1]
2	          no-default-alpn	No support for default protocol	                          IETF	              [RFC9460, Section 7.1]
3	          port	          Port for alternative endpoint	                            IETF	              [RFC9460, Section 7.2]
4	          ipv4hint	      IPv4 address hints	                                      IETF	              [RFC9460, Section 7.3]
5	          ech	            RESERVED (held for Encrypted ClientHello)	                IETF	              [RFC9460]
6	          ipv6hint	      IPv6 address hints	                                      IETF	              [RFC9460, Section 7.3]
7	          dohpath	        DNS over HTTPS path template	                            IETF	              [RFC9461]
8	          ohttp	          Denotes that a service operates an Oblivious HTTP target	IETF	              [RFC-ietf-ohai-svcb-config-07, Section 4]
9-65279	    Unassigned			
65280-65534	N/A	Reserved for Private Use	IETF	[RFC9460]
65535	N/A	Reserved ("Invalid key")	IETF	[RFC9460]

Stretch goal: Add support for key number 7, dohpath. 

#>




class DnsSvcbHttpsSvcParam {
  ## PROPERTIES ##
  #region PROPERTIES

  [List[DnsSvcbHttpsMandatoryKeyName]]
  $Mandatory

  [List[DnsSvcbHttpsAlpn]]
  $ALPN

  [bool]
  $NoALPN

  [int32]
  $Port

  [List[ipaddress]]
  $IPv4Hint

  [List[ipaddress]]
  $IPv6Hint

  # ECH keys are not supported ... yet
  #[List[<something>]]
  #$Keys


  # used by DnsSvcbHttps to determine if the class has been created
  hidden
  $Enabled = $true
  
  #endregion PROPERTIES

  ### CONSTRUCTORS ###
  #region CONSTRUCTORS

  DnsSvcbHttpsSvcParam() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam] - Empty constructor.")
    $this.Mandatory = [List[DnsSvcbHttpsMandatoryKeyName]]::new()
    $this.ALPN      = [List[DnsSvcbHttpsAlpn]]::new()
    $this.NoALPN    = $false
    $this.Port      = -1
    $this.IPv4Hint  = [List[ipaddress]]::new()
    $this.IPv6Hint  = [List[ipaddress]]::new()
    $this.Enabled   = $true
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam] - End.")
  }

  #endregion CONSTRUCTORS

  ### METHODS ###
  #region METHODS

  ### SETTERS and GETTERS ###
  #region get/set
  hidden 
  SetSuccess() {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetSuccess() - Success Code: STATUS_SUCCESS")
  }

  hidden
  SetSuccess([string]$code) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetSuccess() - Success Code: $code")
  }

  hidden
  [System.Management.Automation.ErrorRecord]
  SetError ([string]$code, [string]$message, [string]$module) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetError - Error Code    : $code")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetError - Error Message : $message")

    # record the error in the script wide data stream
    $txt = "[DnsSvcbHttpsSvcParam].$module - $message"
    $script:Common.NewError("DnsSvcbHttpsSvcParam", $module, $code, $message)

    # terminate execution
    return (Write-Error -Message $txt -EA Stop)
  }

  hidden 
  SetWarning ([string]$code, [string]$message, [string]$module) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetWarning - Warning Code    : $code")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetWarning - Warning Message : $message")

    # record the warning in the script wide data stream
    $script:Common.NewWarning("DnsSvcbHttpsSvcParam", $module, $code, $message)
  }
  #endregion get/set

  ## VALIDATORS ##
  #region VALIDATORS
  hidden
  [DnsSvcbHttpsAlpn]
  Validate_ALPN([string]$ALPN) {
    # accept either DnsSvcbHttpsAlpn format or IANA ALPN format
    if ( $script:ianaALPN.alpnEnum -contains $ALPN ) { 
      return $ALPN
    } elseif ( $script:ianaALPN.alpnStr -contains $ALPN ) {
      # convert the value to a key using the code that converts the value to a valid enum
      $aKey = $script:ianaALPN | Where-Object alpnStr -eq $ALPN
      return ($aKey.alpnEnum)
    } else {
      # throw a warning
      $this.SetError("INVALID_ALPN", "The ALPN ($ALPN) was not found on the approved list.", "Validate_ALPN")
      # don't add the ALPN to the SvcParam
      return $null
    }
  }

  hidden
  [bool]
  Validate_Port([int32]$port) {
    # the port must be "a single decimal integer between 0 and 65535"
    if ( $port -ge 0 -and $port -le 65535 ) {
      return $true
    } else {
      $this.SetWarning("INVALID_PORT_NUMBER", "The port must be a single decimal integer between 0 and 65535.")
      return $false
    }
  }

  <#
    Key names contain 1-63 characters from the ranges "a"-"z", "0"-"9", and "-". In ABNF [RFC5234]...

    Arbitrary keys can be represented using the unknown-key presentation format "keyNNNNN" where NNNNN 
    is the numeric value of the key type without leading zeros. A SvcParam in this form SHALL be parsed 
    as specified above, and the decoded value SHALL be used as its wire-format encoding.

  hidden
  [bool]
  Validate_KeyName([string]$key) {

    return $true
  }

  hidden
  [bool]
  Validate_KeyValue([string]$key) {

    return $true
  }
  #>

  # mandatory will only work if the SvcParamKey has already been populated
  hidden
  [bool]
  Validate_Mandatory([string]$key) {
    $script:Common.AddLog("[DnsSvcbHttps].Validate_Mandatory - Begin")

    try {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_Mandatory - TryParse $key to [DnsSvcbHttpsMandatoryKeyName].")
      $keyObj = [DnsSvcbHttpsMandatoryKeyName]$key
      $script:Common.AddLog("[DnsSvcbHttps].Validate_Mandatory - Success! Does the key have a value?")

      switch ($keyObj) {
        alpn {
          if ($this.ALPN.Count -le 0) {
            $this.SetWarning("MANDATORY_ALPN_EMPTY", "The ALPN list is empty. Please add at least one ALPN before making it mandatory.", "Validate_Mandatory")
            return $false
          }
        }

        port {
          if ( $this.Port -lt 0 -and $this.Port -gt 65535 ) {
            $this.SetWarning("MANDATORY_PORT_EMPTY", "The Port is not in in a valid range. Please add a valid Port before making it mandatory.", "Validate_Mandatory")
            return $false
          }
        }

        ipv4hint {
          if ($this.IPv4Hint.Count -le 0) {
            $this.SetWarning("MANDATORY_IPV4HINT_EMPTY", "The IPv4Hint list is empty. Please add at least one IPv4Hint before making it mandatory.", "Validate_Mandatory")
            return $false
          }
        }

        ipv6hint {
          if ($this.IPv6Hint.Count -le 0) {
            $this.SetWarning("MANDATORY_IPV6HINT_EMPTY", "The IPv6Hint list is empty. Please add at least one IPv6Hint before making it mandatory.", "Validate_Mandatory")
            return $false
          }
        }

        default {
          $this.SetError("UNKNOWN_MANDATORY_KEY", "The Mandatory key is unknown. The key ($key) was found in the DnsSvcbHttpsMandatoryKeyName but is missing from the validate switch()", "Validate_Mandatory")
          $this.Result = "The key ($key) was found in the DnsSvcbHttpsMandatoryKeyName but is missing from the validate switch()."
          return $false
        }
      }

      $script:Common.AddLog("[DnsSvcbHttps].Validate_Mandatory - Success! Add the key name to mandatory.")
      return $true
    } catch {
      # not a supported mandatory key, or an invalid name
      $this.SetWarning("INVALID_MANDATORY_KEY_NAME", "The key name ($key) is not a member of [DnsSvcbHttpsMandatoryKeyName]. Valid key names are: $([DnsSvcbHttpsMandatoryKeyName].GetEnumNames() -join ', ')", "Validate_Mandatory")
      return $false
    }

    $script:Common.AddLog("[DnsSvcbHttps].Validate_Mandatory - End")
    return $true
  }

  #endregion VALIDATORS

  ## ADDERS ##
  #region ADDERS

  AddMandatory([string]$mand) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Begin!")

    if ( $this.Validate_Mandatory($mand) ) {
      [DnsSvcbHttpsMandatoryKeyName]$mandStr = $mand

      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - mandStr: $mandStr")

      if ( $mandStr -is [DnsSvcbHttpsMandatoryKeyName] -and $mandStr -notin $this.Mandatory ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Adding $mandStr to ALPN list.")
        $this.Mandatory.Add($mandStr)
      } elseif ( $mandStr -notin $this.Mandatory ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - The Mandatory ($mandStr) has already been added. Current list: $($this.Mandatory -join ', ')")
      } else {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Failed to convert $mandStr to type DnsSvcbHttpsMandatoryKeyName.")
      }
    } else {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Validation failed.")
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - End.")

  }

  AddMandatory([DnsSvcbHttpsMandatoryKeyName]$mand) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(enum) - Begin!")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(enum) - Adding $mand to the Mandatory list.")

    $this.Mandatory.Add($mand)

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(enum) - End.")
  }

  # create methods to catch various array inputs
  AddMandatory([array]$alpn)             { $this.AddMandatoryVoid($alpn) }
   
  AddMandatory([arraylist]$alpn)         { $this.AddMandatoryVoid($alpn) }
   
  AddMandatory([List[Object]]$alpn)      { $this.AddMandatoryVoid($alpn) }
   
  AddMandatory([List[string]]$alpn)      { $this.AddMandatoryVoid($alpn) }

  AddMandatory([List[DnsSvcbHttpsAlpn]]$alpn) { $this.AddMandatoryVoid($alpn) }

  # handles adding an array of ALPNs
  hidden
  AddMandatoryVoid($mandArr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatoryVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($mandArr) ) {
      foreach ( $mand in $mandArr ) {
        $valMand = $this.Validate_Mandatory($mand)
        if ( $valMand ) {
          [DnsSvcbHttpsMandatoryKeyName]$mandStr = $mand

          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - mandStr: $mandStr")

          if ( $mandStr -is [DnsSvcbHttpsMandatoryKeyName] -and $mandStr -notin $this.Mandatory ) {
            $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Adding $mandStr to Mandatory list.")
            $this.Mandatory.Add($mandStr)
          } elseif ( $mandStr -notin $this.Mandatory ) {
            $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - The Mandatory ($mandStr) has already been added. Current list: $($this.Mandatory -join ', ')")
          } else {
            $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Failed to convert $mandStr to type DnsSvcbHttpsMandatoryKeyName.")
          }
        } else {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatory(str) - Validation failed.")
        }
      }
    }
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddMandatoryVoid(void) - End.")
  }

  ## handle ALPN
  AddALPN([string]$alpn) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(str) - Begin!")
    
    $alpnStr = $this.Validate_ALPN($alpn)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(str) - alpnStr: $alpnStr")

    if ( $alpnStr -is [DnsSvcbHttpsAlpn] -and $alpnStr -notin $this.ALPN ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(str) - Adding $alpnStr to ALPN list.")
      $this.ALPN.Add($alpnStr)
    } elseif ( $alpnStr -notin $this.ALPN ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(str) - The ALPN ($alpn) has already been added. Current list: $($this.ALPN -join ', ')")
    } else {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(str) - Failed to convert $alpn to type DnsSvcbHttpsAlpn.")
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(str) - End.")
  }

  AddALPN([DnsSvcbHttpsAlpn]$alpn) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(enum) - Begin!")
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(enum) - alpn: $alpn")

    $this.ALPN += $alpn

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddALPN(enum) - End.")
  }

  # create methods to catch various array inputs
  AddALPN([array]$alpn)             { $this.AddAlpnVoid($alpn) }
   
  AddALPN([arraylist]$alpn)         { $this.AddAlpnVoid($alpn) }
   
  AddALPN([List[Object]]$alpn)      { $this.AddAlpnVoid($alpn) }
   
  AddALPN([List[string]]$alpn)      { $this.AddAlpnVoid($alpn) }

  AddALPN([List[DnsSvcbHttpsAlpn]]$alpn) { $this.AddAlpnVoid($alpn) }

  # handles adding an array of ALPNs
  hidden
  AddAlpnVoid($alpnArr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - Begin!")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - alpnArr:`n$($alpnArr)")

    if ( $this.IsSupportedArrayType($alpnArr) ) {
      foreach ( $alpn in $alpnArr ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - Validate ALPN $alpn")
        $alpnStr = $this.Validate_ALPN($alpn)
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - alpnStr: $alpnStr")

        if ( $alpnStr -is [DnsSvcbHttpsAlpn] -and $alpnStr -notin $this.ALPN ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - Adding $alpnStr to ALPN list.")
          $this.ALPN.Add($alpnStr)
        } elseif ( $alpnStr -in $this.ALPN ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - The ALPN ($alpn) has already been added. Current list: $($this.ALPN -join ', ')")
        } else {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - Failed to convert $alpn to type DnsSvcbHttpsAlpn.")
        }
      }
    # single object lists and arrays don't always play nice so this elseif is a fail safe.
    } elseif ( $alpnArr.Count -eq 1 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - Single object in generic list, calling the enum version of AddAlpn.")
      $alpnStr = $alpnArr[0]
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - alpnStr: $alpnStr")
      $this.AddALPN($alpnStr)
    }
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddAlpnVoid(void) - End.")
  }

  # handles NoALPN
  <#
    https://www.rfc-editor.org/rfc/rfc9460#name-representation

      For "no-default-alpn", the presentation and wire-format values MUST be empty. 
      When "no-default-alpn" is specified in an RR, "alpn" must also be specified in order for 
      the RR to be "self-consistent" (Section 2.4.3).
  #>
  AddNoALPN([bool]$state) {
    $this.NoALPN = $state
  }

  ## handle port
  AddPort([int32]$port) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddPort - Begin!")
    
    # validate the port
    if ( $this.Validate_Port($port) ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddPort - Port validated. Adding the port.")
      $this.Port = $port
    } else {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddPort - Port ($port) validation failed.")
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddPort - End.")
  }


  ## handle IPv4 hints
  AddIpv4Hint([string]$addr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - Begin!")
    
    $addr4 = $script:Common.Validate_IPv4Address($addr)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - addr4: $addr4")

    if ( $addr4 -is [ipaddress] -and $addr4.IPAddressToString -notin $this.IPv4Hint.IPAddressToString ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - Adding $($addr4.IPAddressToString) to IPv4Hints list.")
      $this.IPv4Hint += $addr4
    } elseif ( $addr4.IPAddressToString -in $this.IPv4Hint.IPAddressToString ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - The address ($addr) has already been added to IPv4Hints.")
    } else {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - Failed to convert $addr to an IPv4 address.")
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4Hint(str) - End.")
  }

  # create methods to catch various array inputs
  AddIpv4Hint([array]$addr)           { $this.AddIpv4HintVoid($addr) }
   
  AddIpv4Hint([arraylist]$addr)       { $this.AddIpv4HintVoid($addr) }
   
  AddIpv4Hint([List[Object]]$addr)    { $this.AddIpv4HintVoid($addr) }
   
  AddIpv4Hint([List[string]]$addr)    { $this.AddIpv4HintVoid($addr) }

  AddIpv4Hint([List[ipaddress]]$addr) { $this.AddIpv4HintVoid($addr) }

  # handles adding an array of IPv4 Hints
  hidden
  AddIpv4HintVoid($addrArr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($addrArr) ) {
      foreach ( $addr in $addrArr ) {
        $addr4 = $script:Common.Validate_IPv4Address($addr)
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - addr4: $addr4")

        if ( $addr4 -is [ipaddress] -and $addr4.IPAddressToString -notin $this.IPv4Hint.IPAddressToString ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - Adding $($addr4.IPAddressToString) to IPv4Hints list.")
          $this.IPv4Hint += $addr4
        } elseif ( $addr4.IPAddressToString -in $this.IPv4Hint.IPAddressToString ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - The address ($addr) has already been added to IPv4Hints.")
        } else {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - Failed to convert $addr to an IPv4 address. Skipping this entry.")
        }
      }
    }
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv4HintVoid(void) - End.")
  }


  ## handle IPv6 hints
  AddIpv6Hint([string]$addr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - Begin!")
    
    $addr6 = $script:Common.Validate_IPv6Address($addr)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - addr4: $addr6")

    if ( $addr6 -is [ipaddress] -and $addr6.IPAddressToString -notin $this.IPv6Hint.IPAddressToString ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - Adding $($addr6.IPAddressToString) to IPv6Hints list.")
      $this.IPv6Hint += $addr6
    } elseif ( $addr6.IPAddressToString -in $this.IPv6Hint.IPAddressToString ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - The address ($addr) has already been added to IPv6Hints.")
    } else {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - Failed to convert $addr to an IPv6 address.")
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6Hint(str) - End.")
  }

  # create methods to catch various array inputs
  AddIpv6Hint([array]$addr)           { $this.AddIpv6HintVoid($addr) }
   
  AddIpv6Hint([arraylist]$addr)       { $this.AddIpv6HintVoid($addr) }
   
  AddIpv6Hint([List[Object]]$addr)    { $this.AddIpv6HintVoid($addr) }
   
  AddIpv6Hint([List[string]]$addr)    { $this.AddIpv6HintVoid($addr) }

  AddIpv6Hint([List[ipaddress]]$addr) { $this.AddIpv6HintVoid($addr) }

  # handles adding an array of IPv4 Hints
  hidden
  AddIpv6HintVoid($addrArr) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($addrArr) ) {
      foreach ( $addr in $addrArr ) {
        $addr6 = $script:Common.Validate_IPv6Address($addr)
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - addr6: $addr6")

        if ( $addr6 -is [ipaddress] -and $addr6.IPAddressToString -notin $this.IPv6Hint.IPAddressToString ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - Adding $($addr6.IPAddressToString) to IPv6Hints list.")
          $this.IPv6Hint += $addr6
        } elseif ( $addr6.IPAddressToString -in $this.IPv6Hint.IPAddressToString ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - The address ($addr) has already been added to IPv6Hints.")
        } else {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - Failed to convert $addr to an IPv6 address. Skipping this entry.")
        }
      }
    }
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].AddIpv6HintVoid(void) - End.")
  }


  #endregion ADDERS

  ## CLEAR ##
  #region CLEAR

  ClearMandatory() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ClearMandatory - Clearing all ALPNs.")
    $this.Mandatory.Clear()
  }

  ClearALPN() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ClearALPN - Clearing all ALPNs.")
    $this.ALPN.Clear()

    # update Mandatory
    $this.Update_Mandatory('alpn')
  }

  ClearPort() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ClearPort - Clearing Port.")
    $this.Port = -1

    # update Mandatory
    $this.Update_Mandatory('port')
  }

  ClearIPv4Hint() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ClearIPv4Hint - Clearing all IPv4Hints.")
    $this.IPv4Hint.Clear()

    # update Mandatory
    $this.Update_Mandatory('ipv4hint')
  }

  ClearIPv6Hint() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ClearIPv6Hint - Clearing all IPv6Hints.")
    $this.IPv6Hint.Clear()

    # update Mandatory
    $this.Update_Mandatory('ipv6hint')
  }

  Clear() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Clear - Clearing all keys.")
    $this.ClearMandatory()
    $this.ClearALPN()
    $this.ClearIPv4Hint()
    $this.ClearIPv6Hint()
    $this.ClearPort()
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Clear - End.")
  }

  #endregion CLEAR

  ## REMOVE ##
  #region REMOVE

  # call ClearPort(), because there can be only one Port ... so remove and clear do the same thing
  RemovePort() {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemovePort - Calling ClearPort()")
    $this.ClearPort()
  }

  RemoveALPN([DnsSvcbHttpsAlpn]$str) {
    # is the ALPN in the list
    $isFnd = $this.ALPN.Contains($str)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - Was $str found in list ($($this.ALPN -join ', ')): $isFnd")

    if ( $isFnd ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - $str was found and being removed.")
      try {
        $this.ALPN.Remove($str)
      } catch {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - Failed to remove $str.")
      }
      
      if ( $this.ALPN.Count -le 0 -and $this.Mandatory -contains 'alpn' ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - No more ALPNs, removing from Mandatory.")
        $this.Update_Mandatory('alpn')
      }
    }
  }

  RemoveIPv4Hint([ipaddress]$addr) {
    # is the IPv4Hint in the list
    $isFnd = $this.IPv4Hint.Contains($addr)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv4Hint - Was $addr found in list ($($this.IPv4Hint -join ', ')): $isFnd")

    if ( $isFnd ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv4Hint - $addr was found and being removed.")
      try {
        $this.IPv4Hint.Remove($addr)
      } catch {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv4Hint - Failed to remove $addr.")
      }   

      if ( $this.IPv4Hint.Count -le 0 -and $this.Mandatory -contains 'ipv4hint' ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - No more IPv4Hints, removing from Mandatory.")
        $this.Update_Mandatory('ipv4hint')
      }
    }
  }

  RemoveIPv6Hint([ipaddress]$addr) {
    # is the IPv6Hint in the list
    $isFnd = $this.IPv6Hint.Contains($addr)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv6Hint - Was $addr found in list ($($this.IPv6Hint -join ', ')): $isFnd")

    if ( $isFnd ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv6Hint - $addr was found and being removed.")
      try {
        $this.IPv6Hint.Remove($addr)
      } catch {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveIPv6Hint - Failed to remove $addr.")
      }   

      if ( $this.IPv6Hint.Count -le 0 -and $this.Mandatory -contains 'ipv6hint' ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveALPN - No more IPv6Hints, removing from Mandatory.")
        $this.Update_Mandatory('ipv6hint')
      }
    }
  }

  RemoveMandatory([DnsSvcbHttpsMandatoryKeyName]$str) {
    # is the Mandatory key in the list
    $isFnd = $this.Mandatory.Contains($str)
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveMandatory - Was $str found in list ($($this.Mandatory -join ', ')): $isFnd")

    if ( $isFnd ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveMandatory - $str was found and being removed.")
      try {
        $this.Mandatory.Remove($str)
      } catch {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].RemoveMandatory - Failed to remove $str.")
      }   
    }
  }

  #endregion REMOVE

  ## UPDATE ##
  #region UPDATE

  Update_Mandatory([DnsSvcbHttpsMandatoryKeyName]$mand) {
    if ( $this.Mandatory.Contains([DnsSvcbHttpsMandatoryKeyName]::$mand) ) {
      $this.Mandatory.Remove([DnsSvcbHttpsMandatoryKeyName]::$mand)
    }
  }

  #endregion UPDATE

  ## CONVERTER ##
  #region CONVERTER

  [string]
  Convert2HexStream() {
    <#
      https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml

      Order of operation must follow IANA key numbering:

      Number      Name 	         
      0	          mandatory	     
      1	          alpn	         
      2	          no-default-alpn
      3	          port	         
      4	          ipv4hint	     
      5	          ech	          [NOT SUPPORTED, in draft.] 
      6	          ipv6hint	     
      7	          dohpath	      [FUTURE]
      8	          ohttp	        [NOT SUPPORTED, in draft.]

      Wire data format: https://www.rfc-editor.org/rfc/rfc9460.html#name-rdata-wire-format
      
    #>

    # stores the SvcParam hex stream
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Begin")
    $hexstream = ""

    <#
      Key 0
      Mandatory

      In wire format, the keys are represented by their numeric values in network byte order, concatenated in strictly increasing numeric order.

      https://github.com/wireshark/wireshark/blob/52c1ebb4e1731b93c0bef71fb9cafe78f175581e/epan/dissectors/packet-dns.c

      Key = 2-octect number in network order = 0000
      Key length = 2-octect total length of all values in network order
      Value = 2-octect key number in numerical order

      Example: mandatory = alpn (1), ipv4hint (4)

      00 00
      00 04
      00 01 00 04
    #>

    if ( $this.Mandatory.Count -gt 0 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding Mandatory key.")
      # add the Mandatory key as a two octet network number.
      $hexstream += '0000'
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Mandatory key. hexStream: $hexStream")

      # add the SvcParam length as a network number: #items * 2-octects/item as a 2-octet network number
      # Example: If Mandatory contains alpn and port, then the length is 0004
      $hexstream += $script:Common.Convert_Int2NetworkNumber( ($this.Mandatory.Count * 2), 2)
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Mandatory length. hexStream: $hexStream")

      foreach ( $mand in $this.Mandatory ) {
        # no value length for mandatory values since all values are 2-octet network numbers.
        try {
          $hexstream += $script:Common.Convert_Int2NetworkNumber( $script:DnsSvcbHttpsMandatoryKeyValue.$mand, 2 )
        } catch {
          $this.SetError("UNKNOWN_MANDATORY_KEY_VALUE", "The SvcParam value for key name $mand could not be found.", "Convert2HexStream")
        }
      }
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Mandatory value. hexStream: $hexStream")
    }


    <#
      Key 1
      ALPN

      In wire format, the ALPN names are in US-ASCII code. Each value has a length. The total value is after the key number.

      This key must be present if no-default-alpn is present. But the RFC does not specify whether there must be an ALPN key.
      If there are no ALPN values the total length will be zero and the key will effectively be skipped. I hope.

      Known good example:

      SvcParam: alpn=h3,h2
        SvcParamKey: alpn (1)
        0000   00 01                                             ..

        SvcParamValue length: 6
        0000   00 06                                             ..

        ALPN length: 2
        0000   02                                                .

        ALPN: h3
        0000   68 33                                             h3

        ALPN length: 2
        0000   02                                                .

        ALPN: h2
        0000   68 32                                             h2
    #>

    if ( $this.ALPN.Count -gt 0 -or $this.NoALPN ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding ALPN to hex stream.")
      # add the ALPN key as a two octet network number.
      $hexstream += '0001'
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - ALPN key. hexStream: $hexStream")

      # add up the total length in number of octets.
      # foreach each item: (1 octect for ALPN length) + length of string
      $totalLen = $this.ALPN.Count
      $script:ianaALPN | Where-Object { $_.alpnEnum -in $this.ALPN } | ForEach-Object { $totalLen += $_.alpnLength }
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - ALPN total length: $totalLen, hexStream: $hexStream")
      $hexstream += $script:Common.Convert_Int2NetworkNumber( $totalLen, 2 )
      
      # add the ALPNs to the hex stream
      # <ALPN len><ALPN in US-ASCII>
      foreach ($a in $this.ALPN) {
        # add the ALPN length
        $tmpALPN = $script:ianaALPN | Where-Object { $_.alpnEnum -in $a }
        $hexstream += $script:Common.Convert_Int2NetworkNumber( $tmpALPN.alpnLength, 1 )

        # add the ALPN in US-ASCII 
        # get the IANA ALPN code based on the enum ALPN
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - a: $a")
        $ALPNobj = $script:ianaALPN | Where-Object alpnStr -eq $a
        if ( -NOT [string]::IsNullOrEmpty($ALPNobj.alpnHexStream) ) {
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - alpnHexStream: $($ALPNobj.alpnHexStream)")
          $hexstream += $ALPNobj.alpnHexStream
        } else {
          $this.SetError("NO_ALPN_HEX_STREAM", "An IANA ALPN hex stream could not be found for $a.", "Convert2HexStream")
        }
      }

      

      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - ALPN value. hexStream: $hexStream")
    }

    <#
      Key 2
      no-default-alpn

      The "no-default-alpn" SvcParamKey Value Must Be Empty. Simply add the  with a length of zero then move on.

      https://www.rfc-editor.org/rfc/rfc9460#name-representation

      For "no-default-alpn", the presentation and wire-format values MUST be empty. 
      When "no-default-alpn" is specified in an RR, "alpn" must also be specified in order for 
      the RR to be "self-consistent" (Section 2.4.3).
    
    #>

    if ( $this.NoALPN ) {
      # add the ALPN key as a two octet network number and a length of zero (0000).
      $hexstream += '00020000'
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - no-default-alpn. hexStream: $hexStream")
    }

    <#
      Key 3
      Port

      Key number (0003), key length will always be 0002, followed by the port number in 2-octet network byte order.
    
    #>

    if ( $this.Port -ge 0 ) {
      # add the key and key length of 2
      $hexstream += "00030002"
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Add Port. hexStream: $hexStream")

      # add the port in netwokr byte order
      $hexstream += $script:Common.Convert_Int2NetworkNumber( $this.Port, 2 )
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Port added. hexStream: $hexStream")
    }

    <#
      Key 4
      ipv4hint

      In wire format, the key (0004), plus total key length (num IPs * 4 octets), plus each IPv4 address as a hex stream of octets.

      $addr = [ipaddress]"104.16.132.229"
      $addrOctets = $addr.GetAddressBytes() | ForEach-Object { "{0:x2}" -f $_ }
      $hextStream +=  ( $addrOctets -join '' )
      
      681084e5


      Known good example (cloudflare.com):

        [In recrod data hex stream.]
        SvcParam: ipv4hint=104.16.132.229,104.16.133.229
            SvcParamKey: ipv4hint (4)
            0000   00 04                                             ..

            SvcParamValue length: 8
            0000   00 08                                             ..

            IP: 104.16.132.229
            0000   68 10 84 e5                                       h...

            IP: 104.16.133.229
            0000   68 10 85 e5                                       h...
    
    #>

    if ( $this.IPv4Hint.Count -gt 0 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding ipv4hint.")
      # add the key number
      $hexstream += "0004"
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv4Hint key. hexStream: $hexStream")

      # add the total length
      $totalLen = $this.IPv4Hint.Count * 4
      $hexstream += $script:Common.Convert_Int2NetworkNumber( $totalLen, 2 )
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv4Hist length. hexStream: $hexStream")

      # add the IPv4 addresses
      foreach ($addr in $this.IPv4Hint) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding $($addr.IPAddressToString)")
        $addrStream = $script:Common.Convert_IPAddress2HexStream($addr)
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - addrStream: $addrStream")
        $hexstream += $addrStream
      }
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv4Hint value. hexStream: $hexStream")
    }



    <#
      Key 6
      ipv6hint

      In wire format, the key (0006), plus total key length (num IPs * 16 octets), plus each IPv6 address as a hex stream of octets. No shortened IPv6 address, all 128-bits must be used.

      Known good example (cloudflare.com):

      [In recrod data hex stream.]
      SvcParam: ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
          SvcParamKey: ipv6hint (6)
          0000   00 06                                             ..

          SvcParamValue length: 32
          0000   00 20                                             . 

          IP: 2606:4700::6810:84e5
          0000   26 06 47 00 00 00 00 00 00 00 00 00 68 10 84 e5   &.G.........h...

          IP: 2606:4700::6810:85e5
          0000   26 06 47 00 00 00 00 00 00 00 00 00 68 10 85 e5   &.G.........h...
    #>

    if ( $this.IPv6Hint.Count -gt 0 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding ipv6hint.")
      # add the key number
      $hexstream += "0006"
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv6Hint key. hexStream: $hexStream")

      # add the total length
      $totalLen = $this.IPv6Hint.Count * 16
      $hexstream += $script:Common.Convert_Int2NetworkNumber( $totalLen, 2 )
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv6Hint length. hexStream: $hexStream")

      # add the IPv6 addresses
      foreach ($addr in $this.IPv6Hint) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - Adding $($addr.IPAddressToString)")
        $addrStream = $script:Common.Convert_IPAddress2HexStream($addr)
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - addrStream: $addrStream")
        $hexstream += $addrStream
      }
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].Convert2HexStream - IPv6Hint value. hexStream: $hexStream")
    }

    return $hexstream
  }

  #endregion CONVERTER

  ## IMPORT ##
  #region IMPORT

  <#
    Number      Name 	          Meaning 	                                                Change Controller 	Reference 
    0	          mandatory	      Mandatory keys in this RR	                                IETF	              [RFC9460, Section 8]
    1	          alpn	          Additional supported protocols	                          IETF	              [RFC9460, Section 7.1]
    2	          no-default-alpn	No support for default protocol	                          IETF	              [RFC9460, Section 7.1]
    3	          port	          Port for alternative endpoint	                            IETF	              [RFC9460, Section 7.2]
    4	          ipv4hint	      IPv4 address hints	                                      IETF	              [RFC9460, Section 7.3]
    5	          ech	            RESERVED (held for Encrypted ClientHello)	                IETF	              [RFC9460]
    6	          ipv6hint	      IPv6 address hints	                                      IETF	              [RFC9460, Section 7.3]
    7	          dohpath	        DNS over HTTPS path template	                            IETF	              [RFC9461]
    8	          ohttp	          Denotes that a service operates an Oblivious HTTP target	IETF	              [RFC-ietf-ohai-svcb-config-07, Section 4]
    9-65279	    Unassigned			
    65280-65534	N/A	Reserved for Private Use	IETF	[RFC9460]
    65535	N/A	Reserved ("Invalid key")	IETF	[RFC9460]
  #>

  # accepts the raw RecordData, including SvcPriority and TargetName, parses the SvcKeys and populates the class properties with the results
  hidden
  ImportSvcParamFromRecordData([string]$RecordData) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - Begin")
    if ( [string]::IsNullOrEmpty($RecordData) ) {
      $this.SetError("EMPTY_RECORDDATA", "The RecordData is null or empty.", "ImportSvcParamFromRecordData")
    }

    # various static length used to convert number of chars to octects in a hex stream
    $octetLen = 2
    $keyLen = $portLen = 2 * $octetLen
    $ipv4Len = 4 * $octetLen
    $ipv6Len = 16 * $octetLen


    # tracks the offset pointer
    # the first four octets are the SvcPriority, skip those and start at the TargetName
    $offset = 4

    # length of the record data
    $rdLen = $RecordData.Length

    # find the first SvcParamKey
    $tnOct = [int]"0x$($RecordData.Substring($offset,$octetLen))"

    if ($tnOct -ne 0) {
      # loop until $tnOct == 0
      do {
        # find the next label length
        $offset += $tnOct * $octetLen + 2
        Write-Host "offset: $offset, data: $($RecordData.Substring($offset,$octetLen))"
        
        $tnOct = [int]"0x$($RecordData.Substring($offset,$octetLen))"
        #Write-Host "tnOct: $tnOct, offset: $offset"
      } until ($tnOct -eq 0 -or $offset -gt $rdLen)

      if ($offset -gt $rdLen) {
        $this.SetError("RECORDDATA_TARGET_MALFORMED", "The TargetName in the RecordData could not be parsed.", "ImportSvcParamFromRecordData")
      }
    } else {
      # increment by 1 octet to move past the TargetName of 00
      $offset += $octetLen
    }

    # tracks key order.
    # throw an error if key are out of order, as that is a protocol violation
    $keyOrder = [List[int]]::new()

    do {
      # get the SvcParamKey: 2-octets = 4 chars
      # error if offset + 4 > length
      if ( ($offset + 4) -gt $rdLen ) {
        $this.SetError("RECORDDATA_OFFSET_BOUNDS", "The RecordData offset was out of bounds. Buffer overflow error.", "ImportSvcParamFromRecordData")
      }

      $key = [int]"0x$($RecordData.Substring($offset,$keyLen))"
      $keyOrder.Add($key)

      # check for key order malformations
      if ( $keyOrder.Count -ge 2 ) {
        # key -1 MUST BE greater than key -2
        if ( $keyOrder[-1] -le $keyOrder[-2] ) {
          $this.SetError("RECORDDATA_KEYS_OUT_OF_ORDER", "The SvcParam keys must be in ascending order, per RFC 9460. Current key: $($keyOrder[-1]), previous key: $($keyOrder[-2])", "ImportSvcParamFromRecordData")
        }

        # check for duplicate keys
        $keyGroup = $keyOrder | Group-Object | Where-Object Count -gt 1
        if ($keyGroup) {
          $this.SetError("RECORDDATA_KEY_DUPLICATION", "The SvcParam keys cannot duplicate, per RFC 9460. Duplicate key number: $($keyGroup.Name) [$($script:DnsSvcbHttpsSvcParamKeys | Where-Object Number -eq $keyGroup.Name | ForEach-Object Name)]", "ImportSvcParamFromRecordData")
        }
      }

      $offset += $keyLen

      switch ($key) {
        # Mandatory
        0 {
          <#
            Key (2-octets) - Performed outside the switch
            Param Length (2-octets)
            SvcParam key numbers (2-octets) until param length reached
          #>
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - mandatory SvcParam found.")
          
          # get the Mandatory len
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"
          $offset += $keyLen

          # find the end of the SvcParam
          $keyEnds = $offset + ($paramLen * $octetLen)

          do {
            # get the SvcParam key
            $key = $script:DnsSvcbHttpsSvcParamKeys | Where-Object { $_.HexStream -eq "$($RecordData.Substring($offset,$keyLen))" }

            if ($key) {
              # add to Mandatory
              $this.AddMandatory($key.enumName)
            } else {
              $this.SetError("RECORDDATA_MANDATORY_MISSING", "The SvcParamKey (0x$($RecordData.Substring($offset,$keyLen))) was not found. This may be an unsupported key.", "ImportSvcParamFromRecordData")
            }

            # update the offset
            $offset += $keyLen
          } until ( $offset -ge $keyEnds)

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_MANDATORY_OVERBUFFER", "mandatory over buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_MANDATORY_UNDERBUFFER", "mandatory under buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          # put the offset point to the start of the next SvcParam
          $offset = $keyEnds

        }
        
        # ALPN
        1 {
          <#
            Key (2-octets) - Performed outside the switch
            Param Length (2-octets)
            Value lngth (1-octet)
            Value (variable based on value length)
            ...repeat parsing values until Param length reached
          #>

          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - alpn SvcParam found.")

          # get the param len
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"
          $offset += $keyLen

          # find the end of the SvcParam
          $keyEnds = $offset + ($paramLen * $octetLen)

          do {
            # get the value length (1 octet)
            $valLen = [int]"0x$($RecordData.Substring($offset,$octetLen))"
            $offset += $octetLen

            # get the value
            $value = $script:Common.Convert_HexStream2String($($RecordData.Substring($offset,$valLen * $octetLen)))

            # add the value to this.ALPN
            $this.AddALPN($value)

            # update the offset
            $offset += $valLen * $octetLen

          } until ( $offset -ge $keyEnds)

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_ALPN_OVERBUFFER", "alpn over buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_ALPN_UNDERBUFFER", "alpn under buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          # put the offset point to the start of the next SvcParam
          $offset = $keyEnds
          
        }

        # no-default-alpn
        2 {
          <#
            Easy button!

            Set NoALPN to true, update the offset, move on.
          #>

          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - no-default-alpn SvcParam found.")

          # the key length must be 0
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"

          # update offset
          $offset += $keyLen

          $this.AddNoALPN($true)
        }

        # port 
        3 {
          <#
            Param length should be 2-octets
            Followed by the 2-octet port
          #>
          
          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - port SvcParam found.")

          # the SvcParam length 
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"

          # update offset
          $offset += $keyLen

          # get the port
          $prt = [int]"0x$($RecordData.Substring($offset,$portLen))"
          $offset += $portLen

          $this.AddPort($prt)
        }

        # ipv4hint
        4 {
          <#
            Param length determines how many IPv4 addresses there are.
            Each IPv4 address is a 4-octets.
          
          #>

          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - ipv4hint SvcParam found.")

          # get the param len
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"
          $offset += $keyLen

          # find the end of the SvcParam
          $keyEnds = $offset + ($paramLen * $octetLen)

          # fail if the paramLen is not a multiple of $ipv4Len
          if ( ($paramLen % $ipv4Len) -ne 0 ) {
            $this.SetError("RECORDDATA_IPV4HINT_MOD_ERROR", "The ipv4hint parameter length is invalid. Not divisilbe by 4-octets.", "ImportSvcParamFromRecordData")
          }

          # extract the IPv4 addresses
          do {
            # get IPv4 addr hex stream
            $addrHex = -1
            try {
              $addrHex = $RecordData.Substring($offset,$ipv4Len)
            } catch {
              $this.SetError("RECORDDATA_IPV4HINT_STREAM_ERROR", "Failed to retrieve the ipv4hint hex stream: $_", "ImportSvcParamFromRecordData")
            }

            # update offset
            $offset += $ipv4Len

            # convert the hex stream to an ipv4 addr
            $addr = $script:Common.Convert_HexStream2IPv4Address($addrHex)

            if ( $addr -is [ipaddress] ) {
              $this.AddIpv4Hint($addr)
            } else {
              $this.SetError("RECORDDATA_IPV4HINT_PARSE_ERROR", "The hex stream ($addrHex) failed to parse to a valid IPv4 address.", "ImportSvcParamFromRecordData")
            }

          } until ( $offset -ge $keyEnds)

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_IPV4HINT_OVERBUFFER", "The ipv4hint(s) over buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_IPVHINT_UNDERBUFFER", "The ipv4hint(s) under buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          # put the offset point to the start of the next SvcParam
          $offset = $keyEnds
        }

        # ipv6hint
        6 {
          <#
            Param length determines how many IPv6 addresses there are.
            Each IPv6 address is a 16-octets.
          
          #>

          $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - ipv6hint SvcParam found.")

          # get the param len
          $paramLen = [int]"0x$($RecordData.Substring($offset,$keyLen))"
          $offset += $keyLen

          # find the end of the SvcParam
          $keyEnds = $offset + ($paramLen * $octetLen)

          # fail if the paramLen is not a multiple of $ipv4Len
          if ( ($paramLen % $ipv6Len) -ne 0 ) {
            $this.SetError("RECORDDATA_IPV6HINT_MOD_ERROR", "The ipv6hint parameter length is invalid. Not divisilbe by 4-octets.", "ImportSvcParamFromRecordData")
          }

          # extract the IPv4 addresses
          do {
            # get IPv6 addr hex stream
            $addrHex = -1
            try {
              $addrHex = $RecordData.Substring($offset,$ipv6Len)
            } catch {
              $this.SetError("RECORDDATA_IPV6HINT_STREAM_ERROR", "Failed to retrieve the ipv6hint hex stream: $_", "ImportSvcParamFromRecordData")
            }
            

            # update offset
            $offset += $ipv6Len

            # convert the hex stream to an ipv4 addr
            $addr = $script:Common.Convert_HexStream2IPv6Address($addrHex)

            if ( $addr -is [ipaddress] ) {
              $this.AddIpv6Hint($addr)
            } else {
              $this.SetError("RECORDDATA_IPV6HINT_PARSE_ERROR", "The hex stream ($addrHex) failed to parse to a valid IPv6 address.", "ImportSvcParamFromRecordData")
            }
          } until ( $offset -ge $keyEnds)

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_IPV6HINT_OVERBUFFER", "The ipv6hint(s) over buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          if ( $offset -gt $keyEnds ) {
            $this.SetError("RECORDDATA_IPV6HINT_UNDERBUFFER", "The ipv6hint(s) under buffer error. Expected offset: $keyEnds, actual offset: $offset", "ImportSvcParamFromRecordData")
          }

          # put the offset point to the start of the next SvcParam
          $offset = $keyEnds
        }

        default {
          $this.SetWarning("SVCPARAMKEY_$key`_NOT_IMPLEMENTED", "The SvcParamKey $key is not yet implemented.", "ImportSvcParamFromRecordData")
        }
      }

      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - offset: $offset, rdLen: $rdLen")
    } until ( $offset -ge ($rdLen - 1) )
    
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].ImportSvcParamFromRecordData - End")
  }

  #endregion IMPORT

  ## UTILITY ##
  #region UTILITY

  [bool]
  hidden
  IsSupportedArrayType($test) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - Begin")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - Type:`n$($test | Out-String)")
    if ( $test -is [array] `
            -or $test -is [arrayList] `
            -or $test.GetType().Name -is 'List`1' 
            #-or $test -is [hashtable]
        ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - Is supported array.")
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - End")
        return $true
    } else {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - Is not a supported array.")
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - End")
        return $false
    }
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].IsSupportedArrayType(1) - End")
  }

  #endregion UTILITY

  ## OUTPUT ##
  #region OUTPUT

  [string]
  ToString() {
    return ($this | Format-List | Out-String)
  }

  [string]
  ToDigString() {
    <#
      Sample dig output:

      alpn="h2,h3" no-default-alpn port=8080 ipv4hint=192.168.100.250,10.20.30.40 ipv6hint=2006:2007:2008:2009::2,2006:2007
    #>
    $str = ""

    if ($this.ALPN.Count -gt 0) {
      $str += "alpn=`"$($this.ALPN -join ',')`" "
    }

    if ($this.NoALPN) {
      $str += "no-default-alpn "
    }

    if ($this.IPv4Hint.Count -gt 0) {
      $str += "ipv4hint=`"$($this.IPv4Hint.IPAddressToString -join ',')`" "
    }

    if ($this.IPv6Hint.Count -gt 0) {
      $str += "ipv6hint=`"$($this.IPv6Hint.IPAddressToString -join ',')`" "
    }
    
    return $str.Trim(' ')
  }

  #endregion OUTPUT

  #endregion METHODS

}



class DnsSvcbHttps {
  ### PROPERTIES ###
  #region PROPERTIES
  [string]
  $RecordName

  [string]
  $ZoneName

  static
  [int]
  $Type = 65

  [int]
  $TTL

  [DnsSvcbHttpsPriority]
  $SvcPriority

  [string]
  $TargetName

  [DnsSvcbHttpsSvcParam]
  $SvcParam

  #endregion PROPERTIES


  ### CONSTRUCTORS ###
  #region
  DnsSvcbHttps() {
    $script:Common.AddLog("[DnsSvcbHttps] - Empty constructor. Using defaults.")
    $this.RecordName   = $null
    $this.ZoneName     = $null
    $this.TTL          = 3600
    $this.SvcPriority  = [DnsSvcbHttpsPriority]"ServiceMode"
    $this.TargetName   = '.'
    $this.SvcParam     = $null
    $script:Common.AddLog("[DnsSvcbHttps] - Constructor end.")
  }

  DnsSvcbHttps(
      [string]$RecordName,
      [string]$ZoneName
  ) {
    $script:Common.AddLog("[DnsSvcbHttps] - Constuctor with RecordName and ZoneName.")
    
    $script:Common.AddLog("[DnsSvcbHttps] - RecordName - $RecordName")
    if ($this.Validate_RecordName($RecordName)) {
      $script:Common.AddLog("[DnsSvcbHttps] - The RecordName is valid.")
      $this.RecordName   = $RecordName
    } else {
      $script:Common.AddLog("[DnsSvcbHttps] - The RecordName is invalid: $($this.Result)")
      $this.RecordName   = $null
    }
    
    
    $script:Common.AddLog("[DnsSvcbHttps] - ZoneName - $ZoneName")
    if ( $this.Validate_ZoneName($ZoneName) ) {
      $script:Common.AddLog("[DnsSvcbHttps] - The ZoneName is valid.")
      $this.ZoneName     = $ZoneName
    } else {
      $script:Common.AddLog("[DnsSvcbHttps] - The ZoneName is invalid: $($this.Result)")
      $this.ZoneName     = $null
    }

    $this.TTL          = 3600
    $this.SvcPriority  = [DnsSvcbHttpsPriority]"ServiceMode"
    $this.TargetName   = '.'
    $this.SvcParam     = $null
    $script:Common.AddLog("[DnsSvcbHttps] - Constructor end.")
  }

  # AliasMode quick create
  DnsSvcbHttps(
      [string]$RecordName,
      [string]$ZoneName,
      [string]$TargetName

  ) {
    $this.RecordName   = $RecordName
    $this.ZoneName     = $ZoneName
    $this.TTL          = 3600
    $this.SvcPriority  = "AliasMode"
    $this.TargetName   = $this.Validate_TargetName($TargetName)
    $this.SvcParam     = $null
  }
  #endregion

  ### METHODS ###
  #region METHODS
  <#
    https://www.rfc-editor.org/rfc/rfc9460#section-7.1

    7.1. "alpn" and "no-default-alpn"
    
    The "alpn" and "no-default-alpn" SvcParamKeys together indicate the set of Application-Layer Protocol Negotiation (ALPN) 
    protocol identifiers [ALPN] and associated transport protocols supported by this service endpoint (the "SVCB ALPN set").

    As with Alt-Svc [AltSvc], each ALPN protocol identifier is used to identify the application protocol and associated suite 
    of protocols supported by the endpoint (the "protocol suite"). The presence of an ALPN protocol identifier in the SVCB ALPN 
    set indicates that this service endpoint, described by TargetName and the other parameters (e.g., "port"), offers service 
    with the protocol suite associated with this ALPN identifier.

    Clients filter the set of ALPN identifiers to match the protocol suites they support, and this informs the underlying 
    transport protocol used (such as QUIC over UDP or TLS over TCP). ALPN protocol identifiers that do not uniquely identify a 
    protocol suite (e.g., an Identification Sequence that can be used with both TLS and DTLS) are not compatible with this 
    SvcParamKey and MUST NOT be included in the SVCB ALPN set.


  #>

  ### SETTERS and GETTERS ###
  #region get/set

  [string]
  GetRecordData() {
    <#
    
      Order or hex stream:

        - SvcPriority
        - TargetName
        - SvcParam
    
    #>

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Building the record data hex stream.")
    $hexStream = ""

    ## Add SvcPriority to hex stream ##
    $SvcPriorityStream = $this.Convert_SvcPriority2HexStream()

    if ( $SvcPriorityStream.Length -eq 4 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Adding SvcPriority stream: $SvcPriorityStream")
      $hexStream += $SvcPriorityStream
    } else {
      $this.SetError("GetRecordData", "FAILED_SVCPRIORITY_STREAM", "Failed to convert the SvcPriority to a hex stream.")
    }

    ## Add TargetName to hex stream ##
    $TNStream = $this.Convert_TargetName2HexStream()

    if ( $TNStream.Length -ge 2 ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Adding TargetName stream: $TNStream")
      $hexStream += $TNStream
    } else {
      $this.SetError("GetRecordData", "FAILED_TARGETNAME_STREAM", "Failed to convert the TargetName to a hex stream.")
    }

    ## Add SvcParam to hex stream ##
    if ( $this.SvcParam.Enabled ) {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Getting SvcParam hex stream.")
      # Add TargetName to hex stream ##
      $SPStream = $this.SvcParam.Convert2HexStream()

      if ( $SPStream.Length -ge 2 ) {
        $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Adding SvcParam stream: $SPStream")
        $hexStream += $SPStream
      } else {
        $this.SetError("GetRecordData", "FAILED_SVCPARAM_STREAM", "Failed to convert the SvcParam to a hex stream.")
      }
    }

    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].GetRecordData - Returning RecordData hex stream: $hexStream")
    return $hexStream
  }

  hidden 
  SetSuccess() {
      $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetSuccess() - Success Code: STATUS_SUCCESS")
  }

  hidden
  SetSuccess([string]$code) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetSuccess() - Success Code: $code")
  }

  hidden 
  SetError ([string]$code, [string]$message, [string]$module) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetError - Error Code    : $code")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetError - Error Message : $message")

    # record the error in the script wide data stream
    $script:Common.NewError("DnsSvcbHttpsSvcParam", $module, $code, $message)
  }

  hidden 
  SetWarning ([string]$code, [string]$message, [string]$module) {
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetWarning - Warning Code    : $code")
    $script:Common.AddLog("[DnsSvcbHttpsSvcParam].SetWarning - Warning Message : $message")

    # record the warning in the script wide data stream
    $script:Common.NewWarning("DnsSvcbHttpsSvcParam", $module, $code, $message)
  }

  #endregion get/set

  ## VALIDATORS ##
  #region VALIDATORS

  hidden
  [bool]
  Validate_IsDnsName([string]$name) {
    <#
      A period is always valid. Return true.
      
      Use [System.Uri]::CheckHostName() for everything else. 

      https://learn.microsoft.com/en-us/dotnet/api/system.uri.checkhostname?view=netframework-4.8.1

      The only acceptable answer is "Dns" to the TargetName. Anything else returns false.
    #>

    $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - Begin")

    try {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - Checking the TargetName: $name")
      $isDnsName = [System.Uri]::CheckHostName($name)
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - isDnsName: $isDnsName")
    } catch {
      $this.TargetName = $null
      $this.SetError("UNKNOWN_TARGETNAME_FAILURE", $_, "Validate_IsDnsName")
      $this.Result = $_
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - CheckHostName failure: $_")
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - End")
      return $false
    }

    if ( $isDnsName -eq "Dns" ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - $name is a DNS name.")
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - End")
      return $true
    } else {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - $name is NOT a DNS name!")
      $script:Common.AddLog("[DnsSvcbHttps].Validate_IsDnsName - End")
      return $false
    }
  }

  hidden
  [bool]
  Validate_TargetName([string]$TargetName) {
    $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - Begin")

    # check for null and empty
    if ( [string]::IsNullOrEmpty($TargetName) ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - TargetName is null or empty. Setting to null and returning false, as this is an invalid TargetName.")
      $this.SetError("INVALID_TARGETNAME", "TargetName is null or empty.", "Validate_TargetName")
      $this.TargetName = $null
      return $false
    }

    # accept a period (.) as a valid TargetName
    if ( $TargetName -eq '.' ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - TargetName is a period. Auto-approve!")

      # set the TargetName
      $this.TargetName = $TargetName

      # clear any targetname errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_TARGETNAME" ) {
        $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - Resetting INVALID_TARGETNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - End")
      return $true
    }

    # check that the TargetName is a valid DNS name
    if ( $this.Validate_IsDnsName($TargetName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the TargetName and return $true
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - The TargetName is a Dns name.")
      $this.TargetName = $TargetName
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - End")

      # clear any targetname errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_TARGETNAME" ) {
        $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - Resetting INVALID_TARGETNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      return $true
    } else {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - CheckHostName was not Dns.")
      $this.TargetName = $null
      $this.SetError("INVALID_TARGETNAME", "TargetName ($TargetName) is not a valid DNS name.", "Validate_TargetName")
      $this.Result = "The TargetName must be a valid DNS name or a period. TargetName: $TargetName"
      $script:Common.AddLog("[DnsSvcbHttps].Validate_TargetName - End")
      return $false
    }
  }

  hidden
  [bool]
  Validate_RecordName([string]$RecordName) {
    $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - Begin")

    # check for null and empty
    if ( [string]::IsNullOrEmpty($RecordName) ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - RecordName is null or empty. Setting to null and returning false, as this is an invalid RecordName.")
      $this.SetError("INVALID_RECORDNAME", "RecordName is null or empty.", "Validate_RecordName")
      $this.Result = "The RecordName is null or empty."
      $this.RecordName = $null
      return $false
    }

    # accept the 'at symbol' (@) as a valid RecordName, as it represents an apex (root/parent) record
    if ( $RecordName -eq '@' ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - RecordName is an apex record. Auto-approve!")

      # set the RecordName
      $this.RecordName = $RecordName

      # clear any RecordName errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_RECORDNAME" ) {
        $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - Resetting INVALID_RECORDNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - End")
      return $true
    }

    # check that the RecordName is a valid DNS name
    if ( $this.Validate_IsDnsName($RecordName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the RecordName and return $true
      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - The RecordName is a Dns name.")
      $this.RecordName = $RecordName

      # clear any RecordName errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_RECORDNAME" ) {
        $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - Resetting INVALID_RECORDNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - End")
      return $true
    } else {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - CheckHostName was not Dns.")
      $this.RecordName = $null
      $this.SetError("INVALID_RECORDNAME", "The record name ($RecordName) is not a valid DNS name.", "Validate_RecordName")
      $this.Result = "The RecordName is invalid. The name must be a valid DNS name or the 'at symbol' (@) for apex records. RecordName: $RecordName"
      $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - End")
      return $false
    }
  }
  
  hidden
  [bool]
  Validate_ZoneName([string]$ZoneName) {
    $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - Begin")

    # check for null, empty, dot, and apex, all of which are invalid for a zone name
    if ( [string]::IsNullOrEmpty($ZoneName) -or $ZoneName -eq '.' -or $ZoneName -eq '@' ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - ZoneName is null, empty, or invalid. Setting to null and returning false, as this is an invalid ZoneName.")
      $this.SetError("INVALID_ZONENAME_EMPTY", "The zone name ($ZoneName) is null, empty, or invalid.", "Validate_ZoneName")
      $this.Result = "The ZoneName is null, empty, or invalid. ZoneName: $ZoneName"
      $this.ZoneName = $null
      return $false
    }

    # does the zone exist on the server?
    $isZoneFnd = Get-DnsServerZone -ZoneName $ZoneName -EA SilentlyContinue
    if ( -NOT $isZoneFnd ) {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - ZoneName, $ZoneName, not found on the server.")
      $this.SetError("ZONENAME_NOT_FOUND", "ZoneName, $ZoneName, was not found on the server.", "Validate_ZoneName")
      $this.Result = "The ZoneName was not found. ZoneName: $ZoneName"
      $this.ZoneName = $null
      return $false
    }

    # check that the ZoneName is a valid DNS name
    if ( $this.Validate_IsDnsName($ZoneName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the TargetName and return $true
      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - The ZoneName is a Dns name.")
      $this.ZoneName = $ZoneName

      # reset any invalid zone errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -match "ZONENAME" ) {
        $script:Common.AddLog("[DnsSvcbHttps].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - End")
      return $true
    } else {
      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - CheckHostName was not Dns.")
      $this.ZoneName = $null
      $this.SetError("INVALID_ZONENAME", "The zone name ($ZoneName) is invalid.", "Validate_ZoneName")
      $this.Result = "The ZoneName must be a valid DNS name or a period. ZoneName: $ZoneName"
      $script:Common.AddLog("[DnsSvcbHttps].Validate_ZoneName - End")
      return $false
    }
  }

  #endregion VALIDATORS

  ## NEW ##
  #region NEW

  NewSvcParam() {
    # must be in ServiceMode
    if ( $this.SvcPriority -eq "AliasMode" ) {
      $this.SetWarning("INVALID_SVCPARAM_MODE", "Service Paramters (SvcParam) cannot be added to an AliasMode record.", "NewSvcParam")
      $this.Result = "A SvcParam cannot be added to an AliasMode resource record."
      return
    }

    # create a blank SvcParam
    try {
      $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
    } catch {
      $this.SetError("SVCPARAM_CREATE_FAILED", "Failed to create a new SvcParam: $_", "NewSvcParam")
    }
  }

  #endregion NEW

  ## ADDERS ##
  #region ADDERS

  AddMandatory($mand) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddMandatory - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddMandatory - Using AddMandatory in the SvcParam class.")
      $this.SvcParam.AddMandatory($mand)
    } catch {
      $this.SetError("ADD_MANDATORY_FAILED", "Failed to add port: $_", "AddMandatory")
    }
  }

  AddALPN($alpn) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddALPN - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddALPN - Using AddALPN in the SvcParam class. ALPN:`n$($alpn | Out-String)")
      $this.SvcParam.AddALPN($alpn)
    } catch {
      $this.SetError("ADD_ALPN_FAILED", "Failed to add port: $_", "AddALPN")
    }
  }

  AddNoALPN([bool]$noAlpn) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddNoALPN - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddNoALPN - Using AddNoALPN in the SvcParam class. NoALPN: $noAlpn")
      $this.SvcParam.AddNoALPN($noAlpn)
    } catch {
      $this.SetError("ADD_NOALPN_FAILED", "Failed to add port: $_", "AddNoALPN")
    }
  }

  AddPort($port) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddPort - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddPort - Using AddPort in the SvcParam class.")
      $this.SvcParam.AddPort($port)
    } catch {
      $this.SetError("ADD_PORT_FAILED", "Failed to add port: $_", "AddPort")
    }
  }

  AddIpv4Hint($addr) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddIpv4Hint - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddIpv4Hint - Using AddIPv4Hint in the SvcParam class.")
      $this.SvcParam.AddIpv4Hint($addr)
    } catch {
      $this.SetError("ADD_IPV4HINT_FAILED", "Failed to add ipv4hint: $_", "AddIpv4Hint")
    }
  }

  AddIpv6Hint($addr) {
    try {
      if ( -NOT $this.SvcParam.Enabled ) {
        $script:Common.AddLog("[DnsSvcbHttps].AddIpv6Hint - Creating the SvcParam class object.")
        $this.SvcParam = [DnsSvcbHttpsSvcParam]::new()
      }

      $script:Common.AddLog("[DnsSvcbHttps].AddIpv6Hint - Using AddIpv6Hint in the SvcParam class.")
      $this.SvcParam.AddIpv6Hint($addr)
    } catch {
      $this.SetError("ADD_IPV6HINT_FAILED", "Failed to add ipv6hint: $_", "AddIpv6Hint")
    }
  }

  AddTargetName([string]$tn) {
    if ( $this.Validate_TargetName($tn) ) {
      $script:Common.AddLog("[DnsSvcbHttps].AddTargetName - Setting the Targetname to: $tn")
      $this.TargetName = $tn
    }
  }

  #endregion ADDERS

  ## CONVERTERS ##
  #region CONVERTERS

  [string]
  Convert_String2HexStream([string]$str) {
    $script:Common.AddLog("[DnsSvcbHttps].Convert_String2HexStream - string to convert: $str")
    # ('h2'.ToCharArray() | ForEach-Object { '{0:x2}' -f [byte][char]$_ }) -join ''

    if ( [string]::IsNullOrEmpty($str) ) {
      $this.SetWarning("HEX_EMPTY_STRING", "The string is null or empty. Nothing to convert.", "Convert_String2HexStream")
      $script:Common.AddLog("[DnsSvcbHttps].Convert_String2HexStream - The string is null or empty. Nothing to convert.")
      return $null
    }

    $charizard = $str.ToCharArray() | ForEach-Object { '{0:x2}' -f [byte][char]$_ }

    if ( $charizard.Count -gt 0 ) {
      $hexStream = $charizard -join ''
      $script:Common.AddLog("[DnsSvcbHttps].Convert_String2HexStream - hexStream: $hexStream")
      return $hexStream
    } else {
      $this.SetWarning("HEX_NO_STRING_TO_CONVERT", "The string failed to convert to a hex stream. Char count is 0.", "Convert_String2HexStream")
      $script:Common.AddLog("[DnsSvcbHttps].Convert_String2HexStream - Convert failed, char count is 0.")
      return $null
    }
  }

  [string]
  Convert_DnsName2HexStream([string]$str) {
    #$script:Common.AddLog("[DnsSvcbHttps].Convert_DnsName2HexStream - DNS name to convert: $str")

    if ( [string]::IsNullOrEmpty($str) ) {
      #$this.SetWarning("HEX_EMPTY_STRING", "The string is null or empty. Nothing to convert.", "Convert_DnsName2HexStream")
      #$script:Common.AddLog("[DnsSvcbHttps].Convert_DnsName2HexStream - The string is null or empty. Nothing to convert.")
      return $null
    }

    # split the dns name into labels, removing empty strings created by a terminating period
    $labels = $str.Trim(" ").Split('.') | Where-Object { -NOT [string]::IsNullOrEmpty($_) }

    if ($labels.Count -le 0) {
      return $null
    }

    # convert each label to a hex stream, prefix the char length to the resulting hex strea
    $hexStream = ""
    foreach ($label in $labels) {


      # get the label hex stream
      $tmpStream = $this.Convert_String2HexStream($label)

      # create the hex string for the number of characters
      $tmpLen = "{0:x2}" -f $label.Length

      # add the length and label hex stream to the total hex stream
      $hexStream += "$tmpLen$tmpStream"
    }

    # add 00 to the end of the label stream
    $hexStream += "00"

    return $hexStream
  }

  [string]
  Convert_SvcPriority2HexStream() {
    return ("{0:x4}" -f $this.SvcPriority.value__)
  }

  [string]
  Convert_TargetName2HexStream() {
    if ( $this.TargetName -eq '.' ) {
      return '00'
    } else {
      return ( $this.Convert_DnsName2HexStream($this.TargetName) )
    }
  }

  #endregion CONVERTERS

  ## UTILITY ##
  #region UTILITY

  #endregion UTILITY

  ## OUTPUT ##
  #region OUTPUT

  [string]
  ToString() {
      return ($this | Format-List | Out-String)
  }

  #endregion OUTPUT

  #endregion METHODS

}