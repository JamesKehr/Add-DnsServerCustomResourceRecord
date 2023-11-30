<#

    This class manages adding SeRviCe Binding (SVCB) records.

    SVCB records are used to inform clients what ALPN (Application-Layer Protocol Negotiation) the service uses. This is used primarily by web servers to advertise the version of HTTP, IP address hints, and alternate ports.

#>

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

class DnsSvcb {
    ### PROPERTIES ###
    #region
    [string]
    $Name

    hidden
    static
    [string]
    $Type = "0x00 0x41"

    hidden
    static
    [string]
    $Class = "0x00 0x01"

    [int]
    $TTL

    [int]
    $SvcPriority

    [string]
    $TargetName

    [List[Object]]
    $SvcParam
    #endregion


    ### CONSTRUCTORS ###
    #region
    DnsSvcb() {
        $this.Name        = $null
        $this.TTL         = 3600
        $this.SvcPriority = 1
        $this.TargetName  = $null
        $this.SvcParam    = [List[Object]]::new()
    }

    DnsSvcb(
        [string]$Name
    ) {
        $this.Name        = $Name
        $this.TTL         = 3600
        $this.SvcPriority = 1
        $this.TargetName  = $null
        $this.SvcParam    = [List[Object]]::new()
    }
    #endregion

    ### METHODS ###
    #region
    

    #endregion

}