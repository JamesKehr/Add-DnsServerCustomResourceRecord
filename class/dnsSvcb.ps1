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

# generate the class content --- manual editing of URLs is required
$alpnObj | ConvertTo-JSON | Out-String
#>

# generate the ALPN data
$alpnJSON = @'
[
    {
      "Protocol": "HTTP/0.9",
      "alpnStr": "http/0.9",
      "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x30 0x2e 0x39 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1945"
    },
    {
      "Protocol": "HTTP/1.0",
      "alpnStr": "http/1.0",
      "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x30 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1945"
    },
    {
      "Protocol": "HTTP/1.1",
      "alpnStr": "http/1.1",
      "alpnHex": "0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x31 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9112"
    },
    {
      "Protocol": "SPDY/1",
      "alpnStr": "spdy/1",
      "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x31 ",
      "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1"
    },
    {
      "Protocol": "SPDY/2",
      "alpnStr": "spdy/2",
      "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x32 ",
      "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2"
    },
    {
      "Protocol": "SPDY/3",
      "alpnStr": "spdy/3",
      "alpnHex": "0x73 0x70 0x64 0x79 0x2f 0x33 ",
      "ProtURL": "http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3"
    },
    {
      "Protocol": "Traversal Using Relays around NAT (TURN)",
      "alpnStr": "stun.turn",
      "alpnHex": "0x73 0x74 0x75 0x6E 0x2E 0x74 0x75 0x72 0x6E ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7443"
    },
    {
      "Protocol": "NAT discovery using Session Traversal Utilities for NAT (STUN)",
      "alpnStr": "stun.nat-discovery",
      "alpnHex": "0x73 0x74 0x75 0x6E 0x2E 0x6e 0x61 0x74 0x2d 0x64 0x69 0x73 0x63 0x6f 0x76 0x65 0x72 0x79 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7443"
    },
    {
      "Protocol": "HTTP/2 over TLS",
      "alpnStr": "h2",
      "alpnHex": "0x68 0x32 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9113"
    },
    {
      "Protocol": "HTTP/2 over TCP",
      "alpnStr": "h2c",
      "alpnHex": "0x68 0x32 0x63 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9113"
    },
    {
      "Protocol": "WebRTC Media and Data",
      "alpnStr": "webrtc",
      "alpnHex": "0x77 0x65 0x62 0x72 0x74 0x63 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8833"
    },
    {
      "Protocol": "Confidential WebRTC Media and Data",
      "alpnStr": "c-webrtc",
      "alpnHex": "0x63 0x2d 0x77 0x65 0x62 0x72 0x74 0x63 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8833"
    },
    {
      "Protocol": "FTP",
      "alpnStr": "ftp",
      "alpnHex": "0x66 0x74 0x70 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC959"
    },
    {
      "Protocol": "IMAP",
      "alpnStr": "imap",
      "alpnHex": "0x69 0x6d 0x61 0x70 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC2595"
    },
    {
      "Protocol": "POP3",
      "alpnStr": "pop3",
      "alpnHex": "0x70 0x6f 0x70 0x33 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC2595"
    },
    {
      "Protocol": "ManageSieve",
      "alpnStr": "managesieve",
      "alpnHex": "0x6d 0x61 0x6e 0x61 0x67 0x65 0x73 0x69 0x65 0x76 0x65 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC5804"
    },
    {
      "Protocol": "CoAP",
      "alpnStr": "coap",
      "alpnHex": "0x63 0x6f 0x61 0x70 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8323"
    },
    {
      "Protocol": "XMPP jabber:client namespace",
      "alpnStr": "xmpp-client",
      "alpnHex": "0x78 0x6d 0x70 0x70 0x2d 0x63 0x6c 0x69 0x65 0x6e 0x74 ",
      "ProtURL": "https://xmpp.org/extensions/xep-0368.html"
    },
    {
      "Protocol": "XMPP jabber:server namespace",
      "alpnStr": "xmpp-server",
      "alpnHex": "0x78 0x6d 0x70 0x70 0x2d 0x73 0x65 0x72 0x76 0x65 0x72 ",
      "ProtURL": "https://xmpp.org/extensions/xep-0368.html"
    },
    {
      "Protocol": "acme-tls/1",
      "alpnStr": "acme-tls/1",
      "alpnHex": "0x61 0x63 0x6d 0x65 0x2d 0x74 0x6c 0x73 0x2f 0x31 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8737"
    },
    {
      "Protocol": "OASIS Message Queuing Telemetry Transport (MQTT)",
      "alpnStr": "mqtt",
      "alpnHex": "0x6d 0x71 0x74 0x74 ",
      "ProtURL": "http://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html"
    },
    {
      "Protocol": "DNS-over-TLS",
      "alpnStr": "dot",
      "alpnHex": "0x64 0x6F 0x74 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC7858"
    },
    {
      "Protocol": "Network Time Security Key Establishment, version 1",
      "alpnStr": "ntske/1",
      "alpnHex": "0x6E 0x74 0x73 0x6B 0x65 0x2F 0x31 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC8915"
    },
    {
      "Protocol": "SunRPC",
      "alpnStr": "sunrpc",
      "alpnHex": "0x73 0x75 0x6e 0x72 0x70 0x63 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9289"
    },
    {
      "Protocol": "HTTP/3",
      "alpnStr": "h3",
      "alpnHex": "0x68 0x33 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9114"
    },
    {
      "Protocol": "SMB2",
      "alpnStr": "smb",
      "alpnHex": "0x73 0x6D 0x62 ",
      "ProtURL": "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962"
    },
    {
      "Protocol": "IRC",
      "alpnStr": "irc",
      "alpnHex": "0x69 0x72 0x63 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC1459"
    },
    {
      "Protocol": "NNTP",
      "alpnStr": "nntp",
      "alpnHex": "0x6E 0x6E 0x74 0x70 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC3977"
    },
    {
      "Protocol": "DoQ",
      "alpnStr": "doq",
      "alpnHex": "0x64 0x6F 0x71 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC9250"
    },
    {
      "Protocol": "SIP",
      "alpnStr": "sip/2",
      "alpnHex": "0x73 0x69 0x70 0x2f 0x32 ",
      "ProtURL": "https://datatracker.ietf.org/doc/html/RFC3261"
    },
    {
      "Protocol": "TDS/8.0",
      "alpnStr": "tds/8.0",
      "alpnHex": "0x74 0x64 0x73 0x2f 0x38 0x2e 0x30 ",
      "ProtURL": "[[MS-TDS]: Tabular Data Stream Protocol]"
    },
    {
      "Protocol": "DICOM",
      "alpnStr": "dicom",
      "alpnHex": "0x64 0x69 0x63 0x6f 0x6d ",
      "ProtURL": "https://www.dicomstandard.org/current"
    }
  ]
'@

$script:ALPN = $alpnJSON | ConvertFrom-Json


<#

$formALPNStr = $ALPN.alpnStr -replace "[\-|\.|\\|\/]",'_'

@"
enum DnsSvcbAlpn {
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

enum DnsSvcbAlpn {
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

# crete a hashtable of ALPN enums to IANA names
[hashtable]$script:DnsSvcbAlpnStr = @{
  "http_0_9"           = 'http/0.9'
  "http_1_0"           = 'http/1.0'
  "http_1_1"           = 'http/1.1'
  "spdy_1"             = 'spdy/1'
  "spdy_2"             = 'spdy/2'
  "spdy_3"             = 'spdy/3'
  "stun_turn"          = 'stun.turn'
  "stun_nat_discovery" = 'stun.nat-discovery'
  "h2"                 = 'h2'
  "h2c"                = 'h2c'
  "webrtc"             = 'webrtc'
  "c_webrtc"           = 'c-webrtc'
  "ftp"                = 'ftp'
  "imap"               = 'imap'
  "pop3"               = 'pop3'
  "managesieve"        = 'managesieve'
  "coap"               = 'coap'
  "xmpp_client"        = 'xmpp-client'
  "xmpp_server"        = 'xmpp-server'
  "acme_tls_1"         = 'acme-tls/1'
  "mqtt"               = 'mqtt'
  "dot"                = 'dot'
  "ntske_1"            = 'ntske/1'
  "sunrpc"             = 'sunrpc'
  "h3"                 = 'h3'
  "smb"                = 'smb'
  "irc"                = 'irc'
  "nntp"               = 'nntp'
  "doq"                = 'doq'
  "sip_2"              = 'sip/2'
  "tds_8_0"            = 'tds/8.0'
  "dicom"              = 'dicom'
}

enum DnsSvcbPriority {
  AliasMode
  ServiceMode
}


enum DnsSvcbStatus {
  Success
  Error
  Warning
}

enum DnsSvcbWriteType {
  Force
  Append
}


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

class DnsSvcbSvcParam {
  ## PROPERTIES ##
  #region PROPERTIES

  [List[string]]
  $Mandatory

  [List[DnsSvcbAlpn]]
  $ALPN

  [int32]
  $Port

  [List[ipaddress]]
  $IPv4Hint

  [List[ipaddress]]
  $IPv6Hint

  # ECH keys are not supported ... yet
  #[List[<something>]]
  #$Keys
  
  # these params are used to manage the class
  [DnsSvcbStatus]
  $Status

  [string]
  $StatusCode

  [string]
  $Result

  [List[string]]
  $WarningMessage

  [List[string]]
  $Log
  
  #endregion PROPERTIES

  ### CONSTRUCTORS ###
  #region CONSTRUCTORS

  DnsSvcbSvcParam() {
    $this.AddLog("[DnsSvcbSvcParam] - Empty constructor.")
    $this.Mandatory = $null
    $this.ALPN      = $null
    $this.Port      = $null
    $this.IPv4Hint  = $null
    $this.IPv6Hint  = $null
    $this.AddLog("[DnsSvcbSvcParam] - End.")
  }

  #endregion CONSTRUCTORS


  ### METHODS ###
  #region METHODS

  ### SETTERS and GETTERS ###
  #region get/set
  hidden 
  SetSuccess() {
      $this.Status = "Success"
      $this.AddLog("[DnsSvcbSvcParam].SetSuccess() - Code: STATUS_SUCCESS")
      $this.StatusCode = "STATUS_SUCCESS"
  }

  SetSuccess([string]$code) {
    $this.Status = "Success"
    $this.AddLog("[DnsSvcbSvcParam].SetSuccess() - Code: $code")
    $this.StatusCode = $code
  }

  hidden 
  SetError ([string]$code) {
    $this.Status = "Error"
    $this.AddLog("[DnsSvcbSvcParam].SetError - Code: $code")
    $this.StatusCode = $code
  }

  hidden 
  SetWarning ([string]$code, [string]$message) {
    $this.Status = "Warning"
    $this.AddLog("[DnsSvcbSvcParam].SetWarning - Code: $code")
    $this.AddLog("[DnsSvcbSvcParam].SetWarning - WarningMessage: $message")
    $this.WarningMessage += $message
    $this.StatusCode = $code
  }
  #endregion get/set

  ## VALIDATORS ##
  #region VALIDATORS
  hidden
  [DnsSvcbAlpn]
  Validate_ALPN([string]$ALPN) {
    # accept either DnsSvcbAlpn format or IANA ALPN format
    if ( $script:DnsSvcbAlpnStr.ContainsKey($ALPN) ) { \
      return $ALPN
    } elseif ( $script:DnsSvcbAlpnStr.ContainsValue($ALPN) ) {
      # convert the value to a key using the code that converts the value to a valid enum
      $aKey = $ALPN -replace "[\-|\.|\\|\/]",'_'
      return $aKey
    } else {
      # throw a warning
      $this.SetWarning("INVALID_ALPN", "The ALPN ($ALPN) was not found on the approved list.")
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

  hidden
  [ipaddress]
  Validate_IPv4Address([string]$addr) {
    $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - Begin")
    
    # create a reference IPAddress object
    $addr4 = [System.Net.IPAddress]::new(0)

    $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - Try to parse the address: $addr")
    if ( ([System.Net.IPAddress]::TryParse($addr, [ref]$addr4)) ) {
      $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - A valid IP as found. But is it an IPv4 addrress?")

      if ( $addr4.AddressFamily -eq "InterNetwork" ) {
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - The address is IPv4. Success!")
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - End")
        
        if ( $this.Status -ne "Success" -and $this.StatusCode -match "INVALID_IPV4_HINT" ) {
          $this.AddLog("[DnsSvcbSvcParam].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
          $this.Result = $null
          $this.SetSuccess()
        }

        return $addr4
      } else {
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - The address is NOT IPv4. The address is IPv6 and IPv4 is required!!")
        $this.SetError("INVALID_IPV4_HINT_IPV6_FAMILY")
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - End")
        return $null
      }
    } else {
      # not a valid IP address
      $this.SetError("INVALID_IPV4_HINT")
      return $null
    }
  }

  hidden
  [ipaddress]
  Validate_IPv6Address([string]$addr) {
    $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - Begin")
    
    # create a reference IPAddress object
    $addr6 = [System.Net.IPAddress]::new(0)

    $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - Try to parse the address: $addr")
    if ( ([System.Net.IPAddress]::TryParse($addr, [ref]$addr6)) ) {
      $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - A valid IP as found. But is it an IPv6 addrress?")

      if ( $addr6.AddressFamily -eq "InterNetworkv6" ) {
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - The address is IPv6. Success!")

        if ( $this.Status -ne "Success" -and $this.StatusCode -match "INVALID_IPV6_HINT" ) {
          $this.AddLog("[DnsSvcbSvcParam].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
          $this.Result = $null
          $this.SetSuccess()
        }

        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - End")
        return $addr6
      } else {
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - The address is NOT IPv6. The address is IPv4 and IPv6 is required!")
        $this.SetError("INVALID_IPV6_HINT_IPV4_FAMILY")
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - End")
        return $null
      }
    } else {
      # not a valid IP address
      $this.SetError("INVALID_IPV6_HINT")
      return $null
    }
  }

  #endregion VALIDATORS

  ## NEW ##
  #region NEW

  #endregion NEW

  ## ADDERS ##
  #region ADDERS

  ## handle ALPN
  AddALPN([string]$alpn) {
    $this.AddLog("[DnsSvcbSvcParam].AddALPN(str) - Begin!")
    
    $alpnStr = $this.Validate_IPv4Address($alpn)
    $this.AddLog("[DnsSvcbSvcParam].AddALPN(str) - alpnStr: $alpnStr")

    if ( $alpnStr -is [DnsSvcbAlpn] ) {
      $this.AddLog("[DnsSvcbSvcParam].AddALPN(str) - Adding $alpnStr to IPv4Hints list.")
      $this.ALPN += $alpnStr
    } else {
      $this.AddLog("[DnsSvcbSvcParam].AddALPN(str) - Failed to convert $alpn to type DnsSvcbAlpn.")
    }

    $this.AddLog("[DnsSvcbSvcParam].AddALPN(str) - End.")
  }

  AddALPN([DnsSvcbAlpn]$alpn) {
    $this.AddLog("[DnsSvcbSvcParam].AddALPN(enum) - Begin!")
    
    $this.AddLog("[DnsSvcbSvcParam].AddALPN(enum) - alpn: $alpn")

    $this.ALPN += $alpn

    $this.AddLog("[DnsSvcbSvcParam].AddALPN(enum) - End.")
  }

  # create methods to catch various array inputs
  AddALPN([array]$alpn)             { $this.AddIpv4HintVoid($alpn) }
   
  AddALPN([arraylist]$alpn)         { $this.AddIpv4HintVoid($alpn) }
   
  AddALPN([List[Object]]$alpn)      { $this.AddIpv4HintVoid($alpn) }
   
  AddALPN([List[string]]$alpn)      { $this.AddIpv4HintVoid($alpn) }

  AddALPN([List[DnsSvcbAlpn]]$alpn) { $this.AddIpv4HintVoid($alpn) }

  # handles adding an array of ALPNs
  hidden
  AddAlpnVoid($alpnArr) {
    $this.AddLog("[DnsSvcbSvcParam].AddAlpnVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($alpnArr) ) {
      foreach ( $alpn in $alpnArr ) {
        $alpnStr = $this.Validate_ALPN($alpn)
        $this.AddLog("[DnsSvcbSvcParam].AddAlpnVoid(void) - alpnStr: $alpnStr")

        if ( $alpnStr -is [DnsSvcbAlpn] ) {
          $this.AddLog("[DnsSvcbSvcParam].AddAlpnVoid(void) - Adding $alpnStr to ALPN list.")
          $this.ALPN += $alpnStr
        } else {
          $this.AddLog("[DnsSvcbSvcParam].AddAlpnVoid(void) - Failed to convert $alpn to type DnsSvcbAlpn.")
        }
      }
    }
    
    $this.AddLog("[DnsSvcbSvcParam].AddAlpnVoid(void) - End.")
  }


  ## handle port
  AddPort([int32]$port) {
    $this.AddLog("[DnsSvcbSvcParam].AddPort - Begin!")
    
    # validate the port
    if ( $this.Validate_Port($port) ) {
      $this.AddLog("[DnsSvcbSvcParam].AddPort - Port validated. Adding the port.")
      $this.Port = $port
    } else {
      $this.AddLog("[DnsSvcbSvcParam].AddPort - Port ($port) validation failed.")
    }

    $this.AddLog("[DnsSvcbSvcParam].AddPort - End.")
  }


  ## handle IPv4 hints
  AddIpv4Hint([string]$addr) {
    $this.AddLog("[DnsSvcbSvcParam].AddIpv4Hint(str) - Begin!")
    
    $addr4 = $this.Validate_IPv4Address($addr)
    $this.AddLog("[DnsSvcbSvcParam].AddIpv4Hint(str) - addr4: $addr4")

    if ( $addr4 -is [ipaddress] ) {
      $this.AddLog("[DnsSvcbSvcParam].AddIpv4Hint(str) - Adding $($addr4.IPAddressToString) to IPv4Hints list.")
      $this.IPv4Hint += $addr4
    } else {
      $this.AddLog("[DnsSvcbSvcParam].AddIpv4Hint(str) - Failed to convert $addr to an IPv4 address.")
    }

    $this.AddLog("[DnsSvcbSvcParam].AddIpv4Hint(str) - End.")
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
    $this.AddLog("[DnsSvcbSvcParam].AddIpv4HintVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($addrArr) ) {
      foreach ( $addr in $addrArr ) {
        $addr4 = $this.Validate_IPv4Address($addr)
        $this.AddLog("[DnsSvcbSvcParam].AddIpv4HintVoid(void) - addr4: $addr4")

        if ( $addr4 -is [ipaddress] ) {
          $this.AddLog("[DnsSvcbSvcParam].AddIpv4HintVoid(void) - Adding $($addr4.IPAddressToString) to IPv4Hints list.")
          $this.IPv4Hint += $addr4
        } else {
          $this.AddLog("[DnsSvcbSvcParam].AddIpv4HintVoid(void) - Failed to convert $addr to an IPv4 address. Skipping this entry.")
        }
      }
    }
    
    $this.AddLog("[DnsSvcbSvcParam].AddIpv4HintVoid(void) - End.")
  }


  ## handle IPv6 hints
  AddIpv6Hint([string]$addr) {
    $this.AddLog("[DnsSvcbSvcParam].AddIpv6Hint(str) - Begin!")
    
    $addr6 = $this.Validate_IPv6Address($addr)
    $this.AddLog("[DnsSvcbSvcParam].AddIpv6Hint(str) - addr4: $addr6")

    if ( $addr6 -is [ipaddress] ) {
      $this.AddLog("[DnsSvcbSvcParam].AddIpv6Hint(str) - Adding $($addr6.IPAddressToString) to IPv6Hints list.")
      $this.IPv4Hint += $addr6
    } else {
      $this.AddLog("[DnsSvcbSvcParam].AddIpv6Hint(str) - Failed to convert $addr to an IPv6 address.")
    }

    $this.AddLog("[DnsSvcbSvcParam].AddIpv6Hint(str) - End.")
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
    $this.AddLog("[DnsSvcbSvcParam].AddIpv6HintVoid(void) - Begin!")

    if ( $this.IsSupportedArrayType($addrArr) ) {
      foreach ( $addr in $addrArr ) {
        $addr4 = $this.Validate_IPv4Address($addr)
        $this.AddLog("[DnsSvcbSvcParam].AddIpv6HintVoid(void) - addr4: $addr4")

        if ( $addr4 -is [ipaddress] ) {
          $this.AddLog("[DnsSvcbSvcParam].AddIpv6HintVoid(void) - Adding $($addr4.IPAddressToString) to IPv4Hints list.")
          $this.IPv4Hint += $addr4
        } else {
          $this.AddLog("[DnsSvcbSvcParam].AddIpv6HintVoid(void) - Failed to convert $addr to an IPv4 address. Skipping this entry.")
        }
      }
    }
    
    $this.AddLog("[DnsSvcbSvcParam].AddIpv6HintVoid(void) - End.")
  }


  #endregion ADDERS

  ## UTILITY ##
  #region UTILITY

  # write an event to the class log
  # don't use AddLog inside of AddLog
  hidden
  AddLog([string]$txt) {
    if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
      Write-Verbose "$txt"
      $txt = "$($this.Timestamp())`: $txt" 
      $this.Log += $txt
    }
  }

  [bool]
  hidden
  IsSupportedArrayType($test) {
    $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - Begin")
    $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - Type:`n$($this.ArgumentList.GetType() | Out-String)")
    if ( $test -is [array] `
            -or $test -is [arrayList] `
            -or $test.GetType().Name -is 'List`1' 
            #-or $test -is [hashtable]
        ) {
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - Is supported array.")
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - End")
        return $true
    } else {
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - Is not a supported array.")
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - End")
        return $false
    }
    $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType(1) - End")
  }

  [bool]
  hidden
  IsSupportedArrayType() {
    $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - Begin")
    if ( $null -eq $this.ArgumentList ) {
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - Args are NULL. Return false.")
        return $false
    }

    $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - Type:`n$($this.ArgumentList.GetType() | Out-String)")
    if ( $this.ArgumentList -is [array] `
            -or $this.ArgumentList -is [arrayList] `
            -or $this.ArgumentList.GetType().Name -eq 'List`1' 
            #-or $this.ArgumentList -is [hashtable]
        ) {
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - Is supported array.")
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - End")
        return $true
    } else {
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - Is not a supported array.")
        $this.AddLog("[DnsSvcbSvcParam].IsSupportedArrayType() - End")
        return $false
    }
  }

  #endregion UTILITY

  ## OUTPUT ##
  #region OUTPUT
  Write([string]$Filepath, [DnsSvcbWriteType]$Type) {
    # write results to disk
    $this.AddLog("[DnsSvcbSvcParam].Write(2) - Begin")
    
    if ( $Type -eq "Force" ) {
        $this.AddLog("[DnsSvcbSvcParam].Write(2) - Write with Force.")
        $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Force
    } else {
        $this.AddLog("[DnsSvcbSvcParam].Write(2) - Write with Append.")
        $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
    }
    $this.AddLog("[DnsSvcbSvcParam].Write(2) - End")
  }

  Write([string]$Filepath) {
    # write results to disk - default to append
    $this.AddLog("[DnsSvcbSvcParam].Write(1) - Begin")
    $this.AddLog("[DnsSvcbSvcParam].Write(1) - Write with Append.")
    $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
    $this.AddLog("[DnsSvcbSvcParam].Write(1) - End")
  }

  WriteLog([string]$Filepath, [DnsSvcbWriteType]$Type) {
    # write results to disk
    $this.AddLog("[DnsSvcbSvcParam].WriteLog(2) - Begin")
    
    if ( $Type -eq "Force" ) {
      $this.AddLog("[DnsSvcbSvcParam].WriteLog(2) - Write with Force.")
      $this.AddLog("[DnsSvcbSvcParam].WriteLog(2) - End")
      $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Force
    } else {
      $this.AddLog("[DnsSvcbSvcParam].WriteLog(2) - Write with Append.")
      $this.AddLog("[DnsSvcbSvcParam].WriteLog(2) - End")
      $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
    }
  }

  WriteLog([string]$Filepath) {
    # write results to disk - default to append
    $this.AddLog("[DnsSvcbSvcParam].WriteLog(1) - Begin")
    $this.AddLog("[DnsSvcbSvcParam].WriteLog(1) - Write with Append.")
    $this.AddLog("[DnsSvcbSvcParam].WriteLog(1) - End")
    $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
  }

  [string]
  ToString() {
    return ($this | Format-List | Out-String)
  }

  #endregion OUTPUT

  #endregion METHODS

}



class DnsSvcb {
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

  [DnsSvcbPriority]
  $SvcPriority

  [string]
  $TargetName

  [DnsSvcbSvcParam]
  $SvcParam

  # these params are used to manage the class
  [DnsSvcbStatus]
  $Status

  [string]
  $StatusCode

  [string]
  $Result

  [List[string]]
  $WarningMessage

  [List[string]]
  $Log
  #endregion PROPERTIES


  ### CONSTRUCTORS ###
  #region
  DnsSvcb() {
    $this.AddLog("[DnsSvcb] - Empty constructor. Using defaults.")
    $this.RecordName   = $null
    $this.ZoneName     = $null
    $this.TTL          = 3600
    $this.SvcPriority  = $null
    $this.TargetName   = '.'
    $this.SvcParam     = $null
    $this.State        = "Success"
    $this.ErrorMessage = $null
    $this.Result       = $null
    $this.Log          = [List[string]]::new()
    $this.AddLog("[DnsSvcb] - Constructor end.")
  }

  DnsSvcb(
      [string]$RecordName,
      [string]$ZoneName
  ) {
    $this.AddLog("[DnsSvcb] - Constuctor with RecordName and ZoneName.")
    
    $this.AddLog("[DnsSvcb] - RecordName - $RecordName")
    if ($this.Validate_RecordName($RecordName)) {
      $this.AddLog("[DnsSvcb] - The RecordName is valid.")
      $this.RecordName   = $RecordName
    } else {
      $this.AddLog("[DnsSvcb] - The RecordName is invalid: $($this.Result)")
      $this.RecordName   = $null
    }
    
    
    $this.AddLog("[DnsSvcb] - ZoneName - $ZoneName")
    if ( $this.Validate_ZoneName($ZoneName) ) {
      $this.AddLog("[DnsSvcb] - The ZoneName is valid.")
      $this.ZoneName     = $ZoneName
    } else {
      $this.AddLog("[DnsSvcb] - The ZoneName is invalid: $($this.Result)")
      $this.ZoneName     = $null
    }

    $this.TTL          = 3600
    $this.SvcPriority  = $null
    $this.TargetName   = '.'
    $this.SvcParam     = $null
    $this.State        = "Success"
    $this.ErrorMessage = $null
    $this.Result       = $null
    $this.Log          = [List[string]]::new()
    $this.AddLog("[DnsSvcb] - Constructor end.")
  }

  # AliasMode quick create
  DnsSvcb(
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
    $this.State        = "Success"
    $this.ErrorMessage = $null
    $this.Result       = $null
    $this.Log          = [List[string]]::new()
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
  hidden 
  SetSuccess() {
      $this.Status = "Success"
      $this.AddLog("[DnsSvcb].SetSuccess() - Code: STATUS_SUCCESS")
      $this.StatusCode = "STATUS_SUCCESS"
  }

  SetSuccess([string]$code) {
    $this.Status = "Success"
    $this.AddLog("[DnsSvcb].SetSuccess() - Code: $code")
    $this.StatusCode = $code
  }

  hidden 
  SetError ([string]$code) {
    $this.Status = "Error"
    $this.AddLog("[DnsSvcb].SetError - Code: $code")
    $this.StatusCode = $code
  }

  hidden 
  SetWarning ([string]$code, [string]$message) {
    $this.Status = "Warning"
    $this.AddLog("[DnsSvcbSvcParam].SetWarning - Code: $code")
    $this.AddLog("[DnsSvcbSvcParam].SetWarning - WarningMessage: $message")
    $this.WarningMessage += $message
    $this.StatusCode = $code
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

    $this.AddLog("[DnsSvcb].Validate_IsDnsName - Begin")

    try {
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - Checking the TargetName: $name")
      $isDnsName = [System.Uri]::CheckHostName($name)
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - isDnsName: $isDnsName")
    } catch {
      $this.TargetName = $null
      $this.SetError("UNKNOWN_TARGETNAME_FAILURE")
      $this.Result = $_
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - CheckHostName failure: $_")
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - End")
      return $false
    }

    if ( $isDnsName -eq "Dns" ) {
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - $name is a DNS name.")
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - End")
      return $true
    } else {
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - $name is NOT a DNS name!")
      $this.AddLog("[DnsSvcb].Validate_IsDnsName - End")
      return $false
    }
  }

  hidden
  [bool]
  Validate_TargetName([string]$TargetName) {
    $this.AddLog("[DnsSvcb].Validate_TargetName - Begin")

    # check for null and empty
    if ( [string]::IsNullOrEmpty($TargetName) ) {
      $this.AddLog("[DnsSvcb].Validate_TargetName - TargetName is null or empty. Setting to null and returning false, as this is an invalid TargetName.")
      $this.SetError("INVALID_TARGETNAME")
      $this.TargetName = $null
      return $false
    }

    # accept a period (.) as a valid TargetName
    if ( $TargetName -eq '.' ) {
      $this.AddLog("[DnsSvcb].Validate_TargetName - TargetName is a period. Auto-approve!")

      # set the TargetName
      $this.TargetName = $TargetName

      # clear any targetname errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_TARGETNAME" ) {
        $this.AddLog("[DnsSvcb].Validate_TargetName - Resetting INVALID_TARGETNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $this.AddLog("[DnsSvcb].Validate_TargetName - End")
      return $true
    }

    # check that the TargetName is a valid DNS name
    if ( $this.Validate_IsDnsName($TargetName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the TargetName and return $true
      $this.AddLog("[DnsSvcb].Validate_TargetName - The TargetName is a Dns name.")
      $this.TargetName = $TargetName
      $this.AddLog("[DnsSvcb].Validate_TargetName - End")

      # clear any targetname errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_TARGETNAME" ) {
        $this.AddLog("[DnsSvcb].Validate_TargetName - Resetting INVALID_TARGETNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      return $true
    } else {
      $this.AddLog("[DnsSvcb].Validate_TargetName - CheckHostName was not Dns.")
      $this.TargetName = $null
      $this.SetError("INVALID_TARGETNAME")
      $this.Result = "The TargetName must be a valid DNS name or a period. TargetName: $TargetName"
      $this.AddLog("[DnsSvcb].Validate_TargetName - End")
      return $false
    }
  }

  hidden
  [bool]
  Validate_RecordName([string]$RecordName) {
    $this.AddLog("[DnsSvcb].Validate_RecordName - Begin")

    # check for null and empty
    if ( [string]::IsNullOrEmpty($RecordName) ) {
      $this.AddLog("[DnsSvcb].Validate_RecordName - RecordName is null or empty. Setting to null and returning false, as this is an invalid RecordName.")
      $this.SetError("INVALID_RECORDNAME")
      $this.Result = "The RecordName is null or empty."
      $this.RecordName = $null
      return $false
    }

    # accept the 'at symbol' (@) as a valid RecordName, as it represents an apex (root/parent) record
    if ( $RecordName -eq '@' ) {
      $this.AddLog("[DnsSvcb].Validate_RecordName - RecordName is an apex record. Auto-approve!")

      # set the RecordName
      $this.RecordName = $RecordName

      # clear any RecordName errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_RECORDNAME" ) {
        $this.AddLog("[DnsSvcb].Validate_RecordName - Resetting INVALID_RECORDNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $this.AddLog("[DnsSvcb].Validate_RecordName - End")
      return $true
    }

    # check that the RecordName is a valid DNS name
    if ( $this.Validate_IsDnsName($RecordName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the RecordName and return $true
      $this.AddLog("[DnsSvcb].Validate_RecordName - The RecordName is a Dns name.")
      $this.RecordName = $RecordName

      # clear any RecordName errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -eq "INVALID_RECORDNAME" ) {
        $this.AddLog("[DnsSvcb].Validate_RecordName - Resetting INVALID_RECORDNAME to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $this.AddLog("[DnsSvcb].Validate_RecordName - End")
      return $true
    } else {
      $this.AddLog("[DnsSvcb].Validate_RecordName - CheckHostName was not Dns.")
      $this.RecordName = $null
      $this.SetError("INVALID_RECORDNAME")
      $this.Result = "The RecordName is invalid. The name must be a valid DNS name or the 'at symbol' (@) for apex records. RecordName: $RecordName"
      $this.AddLog("[DnsSvcb].Validate_RecordName - End")
      return $false
    }
  }
  
  hidden
  [bool]
  Validate_ZoneName([string]$ZoneName) {
    $this.AddLog("[DnsSvcb].Validate_ZoneName - Begin")

    # check for null, empty, dot, and apex, all of which are invalid for a zone name
    if ( [string]::IsNullOrEmpty($ZoneName) -or $ZoneName -eq '.' -or $ZoneName -eq '@' ) {
      $this.AddLog("[DnsSvcb].Validate_ZoneName - ZoneName is null, empty, or invalid. Setting to null and returning false, as this is an invalid ZoneName.")
      $this.SetError("INVALID_ZONENAME")
      $this.Result = "The ZoneName is null, empty, or invalid. ZoneName: $ZoneName"
      $this.ZoneName = $null
      return $false
    }

    # does the zone exist on the server?
    $isZoneFnd = Get-DnsServerZone -ZoneName $ZoneName -EA SilentlyContinue
    if ( -NOT $isZoneFnd ) {
      $this.AddLog("[DnsSvcb].Validate_ZoneName - ZoneName, $ZoneName, not found on the server.")
      $this.SetError("ZONENAME_NOT_FOUND")
      $this.Result = "The ZoneName was not found. ZoneName: $ZoneName"
      $this.ZoneName = $null
      return $false
    }

    # check that the ZoneName is a valid DNS name
    if ( $this.Validate_IsDnsName($ZoneName) ) {
      # we should only get here if the CheckHostName returned Dns, so set the TargetName and return $true
      $this.AddLog("[DnsSvcb].Validate_ZoneName - The ZoneName is a Dns name.")
      $this.ZoneName = $ZoneName

      # reset any invalid zone errors
      if ( $this.Status -ne "Success" -and $this.StatusCode -match "ZONENAME" ) {
        $this.AddLog("[DnsSvcb].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
        $this.Result = $null
        $this.SetSuccess()
      }

      $this.AddLog("[DnsSvcb].Validate_ZoneName - End")
      return $true
    } else {
      $this.AddLog("[DnsSvcb].Validate_ZoneName - CheckHostName was not Dns.")
      $this.ZoneName = $null
      $this.SetError("INVALID_ZONENAME")
      $this.Result = "The ZoneName must be a valid DNS name or a period. ZoneName: $ZoneName"
      $this.AddLog("[DnsSvcb].Validate_ZoneName - End")
      return $false
    }
  }

  hidden
  [ipaddress]
  Validate_IPv4Address([string]$addr) {
    $this.AddLog("[DnsSvcb].Validate_IPv4Address - Begin")
    
    # create a reference IPAddress object
    $addr4 = [System.Net.IPAddress]::new(0)

    $this.AddLog("[DnsSvcb].Validate_IPv4Address - Try to parse the address: $addr")
    if ( ([System.Net.IPAddress]::TryParse($addr, [ref]$addr4)) ) {
      $this.AddLog("[DnsSvcb].Validate_IPv4Address - A valid IP as found. But is it an IPv4 addrress?")

      if ( $addr4.AddressFamily -eq "InterNetwork" ) {
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - The address is IPv4. Success!")
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - End")
        
        if ( $this.Status -ne "Success" -and $this.StatusCode -match "INVALID_IPV4_HINT" ) {
          $this.AddLog("[DnsSvcb].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
          $this.Result = $null
          $this.SetSuccess()
        }

        return $addr4
      } else {
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - The address is NOT IPv4. The address is IPv6 and IPv4 is required!!")
        $this.SetError("INVALID_IPV4_HINT_IPV6_FAMILY")
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - End")
        return $null
      }
    } else {
      # not a valid IP address
      $this.SetError("INVALID_IPV4_HINT")
      return $null
    }
  }

  hidden
  [ipaddress]
  Validate_IPv6Address([string]$addr) {
    $this.AddLog("[DnsSvcb].Validate_IPv4Address - Begin")
    
    # create a reference IPAddress object
    $addr6 = [System.Net.IPAddress]::new(0)

    $this.AddLog("[DnsSvcb].Validate_IPv4Address - Try to parse the address: $addr")
    if ( ([System.Net.IPAddress]::TryParse($addr, [ref]$addr6)) ) {
      $this.AddLog("[DnsSvcb].Validate_IPv4Address - A valid IP as found. But is it an IPv6 addrress?")

      if ( $addr6.AddressFamily -eq "InterNetworkv6" ) {
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - The address is IPv6. Success!")

        if ( $this.Status -ne "Success" -and $this.StatusCode -match "INVALID_IPV6_HINT" ) {
          $this.AddLog("[DnsSvcb].Validate_RecordName - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
          $this.Result = $null
          $this.SetSuccess()
        }

        $this.AddLog("[DnsSvcb].Validate_IPv4Address - End")
        return $addr6
      } else {
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - The address is NOT IPv6. The address is IPv4 and IPv6 is required!")
        $this.SetError("INVALID_IPV6_HINT_IPV4_FAMILY")
        $this.AddLog("[DnsSvcb].Validate_IPv4Address - End")
        return $null
      }
    } else {
      # not a valid IP address
      $this.SetError("INVALID_IPV6_HINT")
      return $null
    }
  }

  #endregion VALIDATORS

  ## NEW ##
  #region NEW

  NewSvcParam() {
    # must be in ServiceMode
    if ( $this.SvcPriority -eq "AliasMode" ) {
      $this.SetWarning("INVALID_SVCPARAM_MODE")
      $this.Result = "A SvcParam cannot be added to an AliasMode resource record."
      return
    }

    # create a blank SvcParam

  }

  #endregion NEW

  ## ADDERS ##
  #region ADDERS

  AddIpv4Hint() {

  }

  #endregion ADDERS

    ## UTILITY ##
  #region UTILITY

  # write an event to the class log
  # don't use AddLog inside of AddLog
  hidden
  AddLog([string]$txt) {
      if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
          Write-Verbose "$txt"
          $txt = "$($this.Timestamp())`: $txt" 
          $this.Log += $txt
      }
  }

  #endregion UTILITY

  ## OUTPUT ##
  #region OUTPUT
    Write([string]$Filepath, [DnsSvcbWriteType]$Type) {
      # write results to disk
      $this.AddLog("[DnsSvcb].Write(2) - Begin")
      
      if ( $Type -eq "Force" ) {
          $this.AddLog("[DnsSvcb].Write(2) - Write with Force.")
          $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Force
      } else {
          $this.AddLog("[DnsSvcb].Write(2) - Write with Append.")
          $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
      }
      $this.AddLog("[DnsSvcb].Write(2) - End")
  }

  Write([string]$Filepath) {
      # write results to disk - default to append
      $this.AddLog("[DnsSvcb].Write(1) - Begin")
      $this.AddLog("[DnsSvcb].Write(1) - Write with Append.")
      $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
      $this.AddLog("[DnsSvcb].Write(1) - End")
  }

  WriteLog([string]$Filepath, [DnsSvcbWriteType]$Type) {
      # write results to disk
      $this.AddLog("[DnsSvcb].WriteLog(2) - Begin")
      
      if ( $Type -eq "Force" ) {
          $this.AddLog("[DnsSvcb].WriteLog(2) - Write with Force.")
          $this.AddLog("[DnsSvcb].WriteLog(2) - End")
          $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Force
      } else {
          $this.AddLog("[DnsSvcb].WriteLog(2) - Write with Append.")
          $this.AddLog("[DnsSvcb].WriteLog(2) - End")
          $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
      }
  }

  WriteLog([string]$Filepath) {
      # write results to disk - default to append
      $this.AddLog("[DnsSvcb].WriteLog(1) - Begin")
      $this.AddLog("[DnsSvcb].WriteLog(1) - Write with Append.")
      $this.AddLog("[DnsSvcb].WriteLog(1) - End")
      $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
  }

  [string]
  ToString() {
      return ($this | Format-List | Out-String)
  }

  #endregion OUTPUT

  #endregion METHODS

}