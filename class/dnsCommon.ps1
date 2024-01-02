<# 
    The DnsCommon class contains commonly uses methods by DNS.
#>

<#
  TO-DO:
    - Add Pester testing
  
    - Return objects from Class -> Function should contain Success|Warning|Error, any Warning|Error messages, and the results of the operation in a PSCustomObject.
    - Parse the record from DNS Server.
    - Resolve the DNS record from a DNS server.
      - This will take a lot of work since neither Resolve-DnsName not nslookup support SVCB records...
      - This will be a stretch goal for the initial release.
    - Remove the record from DNS Server (or rely on the normal command...?)

    - Build cmdlets/functions
      - The classes handle creation of the record data, and the parsing of hex streams.
      - The functions manage the work against the DNS server(s) and interface with the classes.
    - Convert cmdlets to a module
    
    - Remote DNS server


    Completed tasks:

    - DONE - Finish Mandatory
    - DONE - If a key becomes empty after removing or clearing it, and the key is marked mandatory, remove the key from the Mandatory list.

    - DONE - Add Remove<Key>
    - DONE - Add Clear<Key>

    - DONE - Figure out encoding scheme (ASCII or UTF-8?) :: 
        - ASCII is the answer ... but also PunyCode. 
        - Only ASCII supported initially. Wait for someone asks for Unicode/PunyCode support...? stretch goal?
        - How to convert to PunyCode: https://fredrikengseth.medium.com/how-to-convert-idn-domains-to-ace-encoding-with-powershell-4b91aac1c4b2
        - The rules are not easy: https://en.wikipedia.org/wiki/Internationalized_domain_name
    
    - DONE - Add converts from string to byte char in hex
      
      '{0:x2}' -f [byte][char]'a'

      result: 61

    - DONE - Add converts from byte char to string
      
      [char][byte]"0x61"

      result: a
    
    - DONE - ASCII string to hex stream sample:

      ('h2'.ToCharArray() | ForEach-Object { '{0:x2}' -f [byte][char]$_ }) -join ''

      result: 6832

    - DONE - Hex stream to ASCII string sample:

      ([regex]::Matches('6832', '(?i)[0-9a-f]{2}').Value | ForEach-Object { [char][byte]"0x$_" }) -join ''

      result: h2

    - DONE/ONGOING - Move validators and common tasks to the DnsCommon class.
    - DONE - Create globals for three information streams.
      - SUCCESS - normal logging. Not doing verbose of information for the pusposed of this project.
      - WARNING - For non-terminating errors.
      - ERROR   - For terminating errors.
      - Move AddLog, and Set[Success|Warning|Error] to DnsCommon. 
      - This way all the logging is in one place and removes complexity from creating classes/functions for custom record creation.
    - DONE - Add the record to DNS Server.

    - DONE - Add the creation of the hex stream
      - SvcParam to hex stream
      - Main DnsSvcb to hex stream
      - Combine the hex streams to create the answer record starting with SvcPriority

#>

using namespace System.Collections
using namespace System.Collections.ArrayList
using namespace System.Collections.Generic

enum DnsStatus {
    Success
    Error
    Warning
}

enum DnsWriteType {
    Force
    Append
}


# the Warning and Error classes are simple structures used to track issues with runtime
# warnings are non-terminating
# errors are terminating

class DnsWarning {
    ## PROPERTIES ##
    #region PROPERTIES

    # source of the warning
    [string]
    $Source

    # method/module/function within the source that called the error
    [string]
    $SourceCaller

    # status code of the warning
    [string]
    $StatusCode

    # warning message
    [string]
    $Message

    hidden
    [DateTime]
    $TimeStamp

    # not other logging in here

    #endregion PROPERTIES

    ## CONSTRUCTORS ##
    #region CONSTRUCTORS

    DnsWarning(
        [string]$Source,
        [string]$SourceCaller,
        [string]$StatusCode,
        [string]$Message
    ) {
        $this.Source       = $Source
        $this.SourceCaller = $SourceCaller
        $this.StatusCode   = $StatusCode
        $this.Message      = $Message
        $this.TimeStamp    = (Get-Date)
    }

    #endregion CONSTRUCTORS

    ## METHODS ##
    #region METHODS

    [string]
    Warning_String() {
        return "$($this.Message) [Source: $($this.Source), Caller $($this.SourceCaller)]"
    }

    WriteWarning() {
        Write-Warning -Message $this.Warning_String()
    }

    [string]
    ToString() {
        return $this.Warning_String()
    }

    #endregion METHODS
}
  
class DnsError {
    ## PROPERTIES ##
    #region PROPERTIES

    # source of the warning
    [string]
    $Source

    # method/module/function within the source that called the error
    [string]
    $SourceCaller

    # status code of the warning
    [string]
    $StatusCode

    # warning message
    [string]
    $Message

    hidden
    [DateTime]
    $TimeStamp

    # not other logging in here

    #endregion PROPERTIES

    ## CONSTRUCTORS ##
    #region CONSTRUCTORS

    DnsError(
        [string]$Source,
        [string]$SourceCaller,
        [string]$StatusCode,
        [string]$Message
    ) {
        $this.Source       = $Source
        $this.SourceCaller = $SourceCaller
        $this.StatusCode   = $StatusCode
        $this.Message      = $Message
        $this.TimeStamp    = (Get-Date)
    }

    #endregion CONSTRUCTORS

    ## METHODS ##
    #region METHODS

    [string]
    Error_String() {
        return "$($this.Message) [Source: $($this.Source), Caller $($this.SourceCaller)]"
    }

    WriteError() {
        Write-Warning -Message $this.Error_String()
    }

    [string]
    ToString() {
        return $this.Error_String()
    }

    #endregion METHODS
}

class DnsCommon {

    ## NEW ##
    #region NEW

    NewError(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message
    ) {
        # create the error object
        $obj = [DnsError]::new($module, $function, $code, $message)

        # add to the log
        $this.AddLog($obj.ToString())

        # add to the error stream
        $script:ErrorStream.Add($obj)
    }

    NewWarning( [DnsError]$obj ) {
        # add to the log
        $this.AddLog($obj.ToString())

        # add to the error stream
        $script:WarningStream.Add($obj)
    }

    NewWarning(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message
    ) {
        # create the error object
        $obj = [DnsWarning]::new($module, $function, $code, $message)

        # add to the log
        $this.AddLog($obj.ToString())

        # add to the error stream
        $script:WarningStream.Add($obj)
    }

    NewWarning( [DnsWarning]$obj ) {
        # add to the log
        $this.AddLog($obj.ToString())

        # add to the error stream
        $script:WarningStream.Add($obj)
    }

    #endregion NEW

    ## VALIDATORS ##
    #region VALIDATORS
    [bool]
    Validate_IsDnsName([string]$name) {
        <#
            Use [System.Uri]::CheckHostName() for everything else. 

            https://learn.microsoft.com/en-us/dotnet/api/system.uri.checkhostname?view=netframework-4.8.1

            The only acceptable answer is "Dns". Anything else returns false.
        #>

        $this.AddLog("[DnsCommon].Validate_IsDnsName - Begin")

        try {
            $this.AddLog("[DnsCommon].Validate_IsDnsName - Checking the TargetName: $name")
            $isDnsName = [System.Uri]::CheckHostName($name)
            $this.AddLog("[DnsCommon].Validate_IsDnsName - isDnsName: $isDnsName")
        } catch {
            $this.TargetName = $null
            $this.SetError("UNKNOWN_TARGETNAME_FAILURE", $_, "Validate_IsDnsName")
            $this.Result = $_
            $this.AddLog("[DnsCommon].Validate_IsDnsName - CheckHostName failure: $_")
            $this.AddLog("[DnsCommon].Validate_IsDnsName - End")
            return $false
        }

        if ( $isDnsName -eq "Dns" ) {
            $this.AddLog("[DnsCommon].Validate_IsDnsName - $name is a DNS name.")
            $this.AddLog("[DnsCommon].Validate_IsDnsName - End")
            return $true
        } else {
            $this.AddLog("[DnsCommon].Validate_IsDnsName - $name is NOT a DNS name!")
            $this.AddLog("[DnsCommon].Validate_IsDnsName - End")
            return $false
        }
    }

    [bool]
    Validate_TargetName([string]$TargetName) {
        $this.AddLog("[DnsSvcb].Validate_TargetName - Begin")

        # check for null and empty
        if ( [string]::IsNullOrEmpty($TargetName) ) {
            $this.AddLog("[DnsSvcb].Validate_TargetName - TargetName is null or empty. Setting to null and returning false, as this is an invalid TargetName.")
            $this.SetError("INVALID_TARGETNAME", "TargetName is null or empty.", "Validate_TargetName")
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
            $this.SetError("INVALID_TARGETNAME", "TargetName ($TargetName) is not a valid DNS name.", "Validate_TargetName")
            $this.Result = "The TargetName must be a valid DNS name or a period. TargetName: $TargetName"
            $this.AddLog("[DnsSvcb].Validate_TargetName - End")
            return $false
        }
    }

    [bool]
    Validate_RecordName([string]$RecordName) {
        $this.AddLog("[DnsSvcb].Validate_RecordName - Begin")

        # check for null and empty
        if ( [string]::IsNullOrEmpty($RecordName) ) {
            $this.AddLog("[DnsSvcb].Validate_RecordName - RecordName is null or empty. Setting to null and returning false, as this is an invalid RecordName.")
            $this.SetError("INVALID_RECORDNAME", "RecordName is null or empty.", "Validate_RecordName")
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
            $this.SetError("INVALID_RECORDNAME", "The record name ($RecordName) is not a valid DNS name.", "Validate_RecordName")
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
            $this.SetError("INVALID_ZONENAME_EMPTY", "The zone name ($ZoneName) is null, empty, or invalid.", "Validate_ZoneName")
            $this.Result = "The ZoneName is null, empty, or invalid. ZoneName: $ZoneName"
            $this.ZoneName = $null
            return $false
        }

        # does the zone exist on the server?
        $isZoneFnd = Get-DnsServerZone -ZoneName $ZoneName -EA SilentlyContinue
        if ( -NOT $isZoneFnd ) {
            $this.AddLog("[DnsSvcb].Validate_ZoneName - ZoneName, $ZoneName, not found on the server.")
            $this.SetError("ZONENAME_NOT_FOUND", "ZoneName, $ZoneName, was not found on the server.", "Validate_ZoneName")
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
            $this.SetError("INVALID_ZONENAME", "The zone name ($ZoneName) is invalid.", "Validate_ZoneName")
            $this.Result = "The ZoneName must be a valid DNS name or a period. ZoneName: $ZoneName"
            $this.AddLog("[DnsSvcb].Validate_ZoneName - End")
            return $false
        }
    }

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
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - The address is NOT IPv4. The address is IPv6 and IPv4 is required!")
            $this.SetWarning("INVALID_IPV4_HINT_IPV6_FAMILY", "The address is NOT IPv4. The address is IPv6 and IPv4 is required!", "Validate_IPv4Address")
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv4Address - End")
            return $null
            }
        } else {
            # not a valid IP address
            $this.SetWarning("INVALID_IPV4_HINT", "The value could not be parsed as an IPv4 address.", "Validate_IPv4Address")
            return $null
        }
    }

    hidden
    [ipaddress]
    Validate_IPv6Address([string]$addr) {
        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - Begin")

        # create a reference IPAddress object
        $addr6 = [System.Net.IPAddress]::new(0)

        $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - Try to parse the address: $addr")
        if ( ([System.Net.IPAddress]::TryParse($addr, [ref]$addr6)) ) {
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - A valid IP as found. But is it an IPv6 addrress?")

            if ( $addr6.AddressFamily -eq "InterNetworkv6" ) {
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - The address is IPv6. Success!")

            if ( $this.Status -ne "Success" -and $this.StatusCode -match "INVALID_IPV6_HINT" ) {
                $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - Resetting $($this.StatusCode) to STATUS_SUCCESS.")
                $this.Result = $null
                $this.SetSuccess()
            }

            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - End")
            return $addr6
            } else {
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - The address is NOT IPv6. The address is IPv4 and IPv6 is required!")
            $this.SetWarning("INVALID_IPV6_HINT_IPV4_FAMILY", "The address is NOT IPv6. The address is IPv4 and IPv6 is required!", "Validate_IPv6Address")
            $this.AddLog("[DnsSvcbSvcParam].Validate_IPv6Address - End")
            return $null
            }
        } else {
            # not a valid IPv6 address
            $this.SetWarning("INVALID_IPV6_HINT", "The value could not be parsed as an IPv6 address.", "Validate_IPv6Address")
            return $null
        }
    }

    #endregion VALIDATORS

    ## CONVERTERS ##
    #region CONVERTERS
    [string]
    Convert_String2HexStream([string]$str) {
        $this.AddLog("[DnsCommon].Convert_String2HexStream - string to convert: $str")
        # ('h2'.ToCharArray() | ForEach-Object { '{0:x2}' -f [byte][char]$_ }) -join ''

        if ( [string]::IsNullOrEmpty($str) ) {
            $this.SetWarning("HEX_EMPTY_STRING", "The string is null or empty. Nothing to convert.", "Convert_String2HexStream")
            $this.AddLog("[DnsCommon].Convert_String2HexStream - The string is null or empty. Nothing to convert.")
            return $null
        }

        $charizard = $str.ToCharArray() | ForEach-Object { '{0:x2}' -f [byte][char]$_ }

        if ( $charizard.Count -gt 0 ) {
            $hexStream = $charizard -join ''
            $this.AddLog("[DnsCommon].Convert_String2HexStream - hexStream: $hexStream")
            return $hexStream
        } else {
            $this.SetWarning("HEX_NO_STRING_TO_CONVERT", "The string failed to convert to a hex stream. Char count is 0.", "Convert_String2HexStream")
            $this.AddLog("[DnsCommon].Convert_String2HexStream - Convert failed, char count is 0.")
            return $null
        }
    }

    [string]
    Convert_HexStream2String([string]$stream) {
        $str = ""

        for ($i = 0; $i -lt $stream.Length; $i = $i + 2) {
            $char = $stream.Substring($i, 2)
            $str += [char][byte]"0x$char"
        }

        return $str
    }

    [string]
    Convert_DnsName2HexStream([string]$str) {
        #$this.AddLog("[DnsCommon].Convert_DnsName2HexStream - DNS name to convert: $str")

        if ( [string]::IsNullOrEmpty($str) ) {
            #$this.SetWarning("HEX_EMPTY_STRING", "The string is null or empty. Nothing to convert.", "Convert_DnsName2HexStream")
            #$this.AddLog("[DnsCommon].Convert_DnsName2HexStream - The string is null or empty. Nothing to convert.")
            return $null
        }

        # split the dns name into labels, removing empty strings created by a terminating period
        # double-double check that the string is in lower case as part of this process...
        $labels = $str.ToLower().Trim(" ").Split('.') | Where-Object { -NOT [string]::IsNullOrEmpty($_) }

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
    Convert_Int2NetworkNumber(
        [int]$num,
        [int]$octets
    ) {
        try {
            return ("{0:x$($octets * 2)}" -f $num)
        } catch {
            return ( Write-Host "Failed to convert $num to a network number: $_" -EA Stop )
        }
    }


    [string]
    Convert_IPAddress2HexStream([ipaddress]$addr) {
        $addrOctets = $addr.GetAddressBytes() | ForEach-Object { "{0:x2}" -f $_ }
        return ( $addrOctets -join '' )
    }

    [ipaddress]
    Convert_HexStream2IPv4Address([string]$addrHex) {
        $adrrStr = ""

        for ($i = 0; $i -lt $addrHex.Length; $i += 2 ) {
            $tmpOct = [byte]"0x$($addrHex.Substring($i, 2))"
            $adrrStr += "$tmpOct`."
        }

        $adrrStr = $adrrStr.Trim('.')
        [ipaddress]$addr = 0

        if ( [ipaddress]::TryParse($adrrStr, [ref]$addr) ) {
            return $addr
        } else {
            return $null
        }
        
    }

    [ipaddress]
    Convert_HexStream2IPv6Address([string]$addrHex) {
        $adrrStr = ""

        for ($i = 0; $i -lt $addrHex.Length; $i += 4 ) {
            $tmpOct = $($addrHex.Substring($i, 4))
            $adrrStr += "$tmpOct`:"
        }

        $adrrStr = $adrrStr.Trim(':')
        [ipaddress]$addr = 0

        if ( [ipaddress]::TryParse($adrrStr, [ref]$addr) ) {
            return $addr
        } else {
            return $null
        }
        
    }

    [string]
    Convert_DnsHexStrem2DnsName([string]$stream) {
        $str = ""

        $octLen = 2
        $offset = 0
        $nextNum = 2

        do {
            # get the octet and advance the offset
            $lbl = $stream.Substring($offset, $octLen)
            $offset += $octLen

            # is this octet a number or char?
            # number when offset == next number position
            # otherwise, char
            #echo "offset: $offset, nextNum: $nextNum, lbl: $lbl"
            if ( $offset -eq $nextNum ) {
                $num = [int]"0x$lbl"

                if ($nextNum -ne 2) {
                    #echo "add dot"
                    $str += '.'
                }

                $nextNum = $octLen + $offset + $num * $octLen
                #echo "nextNum: $nextNum, num: $num"
            } else {
                $str += [char][byte]"0x$lbl"
            }
            
        } until ( $lbl -eq "00" )

        return $str
    }

    #endregion CONVERTERS

    ## UTILITY ##
    #region UTILITY

    # get a timestamp
    [string]
    hidden
    Timestamp() {
        return (Get-Date -Format "yyyyMMdd-HH:mm:ss.ffff")
    }

    # write an event to the class log
    # don't use AddLog inside of AddLog
    hidden
    AddLog([string]$txt) {
        if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
            Write-Verbose "$txt"
            $txt = "$($this.Timestamp())`: $txt" 
            $script:MainStream.Add($txt)
        }
    }

    [bool]
  hidden
  IsSupportedArrayType($test) {
    $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - Begin")
    $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - Type:`n$($test | Out-String)")
    if ( $test -is [array] `
            -or $test -is [arrayList] `
            -or $test.GetType().Name -is 'List`1' 
            #-or $test -is [hashtable]
        ) {
        $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - Is supported array.")
        $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - End")
        return $true
    } else {
        $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - Is not a supported array.")
        $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - End")
        return $false
    }
    $script:Common.AddLog("[DnsCommon].IsSupportedArrayType(1) - End")
  }
    #endregion UTILITY

    ## OUTPUT ##
    #region OUTPUT
    Write([string]$Filepath) {
        # write results to disk - default to append
        $this.AddLog("[DnsCommon].Write(1) - Begin")
        $this.AddLog("[DnsCommon].Write(1) - Write with Append.")
        $this.Result | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
        $this.AddLog("[DnsCommon].Write(1) - End")
    }

    WriteLog([string]$Filepath) {
        # write results to disk - default to append
        $this.AddLog("[DnsCommon].WriteLog(1) - Begin")
        $this.AddLog("[DnsCommon].WriteLog(1) - Write with Append.")
        $this.AddLog("[DnsCommon].WriteLog(1) - End")
        $this.Log | Format-Table -AutoSize | Out-String | Out-File "$Filepath" -Append
    }

    [string]
    ToString() {
        return ($this | Format-List | Out-String)
    }

    #endregion OUTPUT
}