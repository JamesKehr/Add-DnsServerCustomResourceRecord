
# import namespaces
using namespace System.Collections
using namespace System.Collections.Generic


# load all the classes
$classFiles = Get-ChildItem "$PSScriptRoot\class" -Filter "*.ps1"

foreach ($file in $classFiles) {
    . "$($file.FullName)"
}

# create the information streams
$script:MainStream    = [List[string]]::new()
#$script:SuccessStream = [List[string]]::new()
$script:WarningStream = [List[DnsWarning]]::new()
$script:ErrorStream   = [List[DnsError]]::new()

# create the main DnsCommon class instance
$script:Common = [DnsCommon]::new()

# this variable maintains a list of all the RR types supported by DnsServerCustomResourceRecord
$script:CustomResourceRecordList = "SVCB (65)"


function Add-DnsServerCustomResourceRecord {
    [CmdletBinding()]
    param (
        ### REQUIRED by all parameter sets ###
        # Resource record name.
        [Parameter(Mandatory=$true,
                    ParameterSetName='SVCBHTTPS')]
        [string]
        $Name,

        # DNS zone name.
        [Parameter(Mandatory=$true,
                    ParameterSetName='SVCBHTTPS')]
        [string]
        $ZoneName,

        ### OPTIONAL for all parameter sets ###
        [Parameter(ParameterSetName='SVCBHTTPS')]
        [int]
        $TimeToLive,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $ReturnRecordData,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $PassThru,

        ### SERVICE BINDING HTTPS RR ###
        # Implements RFC 9460 type 65 HTTPS SVCB-compatible (Service Binding) resource records in Windows DNS Server.
        #region

        # Add a Service Binding (SVCB) resource record.
        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $HTTPS,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [DnsSvcbHttpsPriority]
        $HttpsSvcPriority = "ServiceMode",

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [ValidateLength(1,63)]
        [string]
        $HttpsTargetName = '.',

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [string[]]
        $HttpsMandatory = $null,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        $HttpsALPN = $null,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $HttpsNoDefaultALPN = $null,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [ValidateRange(0,65535)]
        [int32]
        $HttpsPort = -1,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        $HttpsIPv4Hint = $null,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        $HttpsIPv6Hint = $null
        #endregion
        ### END SERVICE BINDING HTTPS RR ###

    )

    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Begin")

    if ( $HTTPS.IsPresent ) {
        $output = Add-DnsServerCustomResourceRecordHttps @PSBoundParameters

        if ( $ReturnRecordData.IsPresent -or $PassThru.IsPresent ) {
            return $output
        }
    } else {
        Write-Warning "Unknown record type.This cmdlet currently supports the following resource record types: $($script:CustomResourceRecordList -join ', ')"
    }
}


<#

    Service Binding (SVCB) HTTPS RR
    DNS RR type 65

    RFCs: 9460, 9461, 9462

    https://www.rfc-editor.org/rfc/rfc9460.html
    https://www.rfc-editor.org/rfc/rfc9461.html
    https://www.rfc-editor.org/rfc/rfc9462.html

    Drafts: 

#>
function Add-DnsServerCustomResourceRecordHttps {
    [CmdletBinding()]
    param (
        ### REQUIRED by all parameter sets ###
        # DNS zone name.
        [Parameter(Mandatory=$true,
                    ParameterSetName='SVCBHTTPS')]
        [string]
        $ZoneName,

        # Resource record name.
        [Parameter(Mandatory=$true,
                    ParameterSetName='SVCBHTTPS')]
        [string]
        $Name,

        
        ### OPTIONAL for all parameter sets ###
        [Parameter(ParameterSetName='SVCBHTTPS')]
        [int]
        $TimeToLive,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $ReturnRecordData,

        [Parameter(ParameterSetName='SVCBHTTPS')]
        [switch]
        $PassThru,


        # Add a Service Binding (SVCB) resource record.
        [switch]
        $HTTPS,

        [DnsSvcbHttpsPriority]
        $HttpsSvcPriority = "ServiceMode",

        [ValidateLength(1,255)]
        [string]
        $HttpsTargetName = '.',

        [string[]]
        $HttpsMandatory = $null,

        $HttpsALPN = $null,

        [switch]
        $HttpsNoDefaultALPN = $null,

        [ValidateRange(0,65535)]
        [int32]
        $HttpsPort = -1,

        $HttpsIPv4Hint = $null,

        $HttpsIPv6Hint = $null
    )

    ### VALIDATION ##
    #region
    # TargetName is not empty/null
    if ( [string]::IsNullOrEmpty($HttpsTargetName) ) {
        $script:Common.AddLog("Add-DnsServerCustomResourceRecord - TargetName is null or empty.")
        return ( Write-Error "Invalid TargetName. The TargetName must be a valid DNS name or a period, which indicates use the effective record." -EA Stop )
    }

    # TargetName is a valid DNS name
    if ( $HttpsTargetName -ne '.') {
        if ( -NOT $script:Common.Validate_IsDnsName($HttpsTargetName) ) {
            return ( Write-Error "Invalid TargetName. The TargetName is not a valid DNS name." -EA Stop )
        }
    }
    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - TargetName validated.")

    # RecordName is a valid DNS name
    if ( -NOT $script:Common.Validate_IsDnsName($Name) -and $Name -ne '@' ) {
        return ( Write-Error "Invalid record Name. The record Name is not a valid DNS name." -EA Stop )
    }
    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - RecordName validated.")

    # ZoneName is a valid DNS name
    if ( -NOT $script:Common.Validate_IsDnsName($ZoneName) ) {
        return ( Write-Error "Invalid TargetName. The TargetName is not a valid DNS name." -EA Stop )
    }
    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - ZoneName initially validated.")
    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Validation done.")
    #endregion

    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding SVCB HTTPS RR.")
    if ($HttpsSvcPriority -eq "ServiceMode") {
        <# Minimum requirements are met:
            - RecordName (mandatory)
            - ZoneName (mandatory)
            - SvcbTargetName (MUST be a period or a DNS name). Default is a period. 
                TargetName:
                The domain name of either the alias target (for AliasMode) or the alternative endpoint (for ServiceMode).
            - The SvcParam is technically optional...?
        #>

        ### MAIN ###
        #region

        # create the DnsSvcbHttps class object using RecordName and ZoneName
        $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Create DnsSvcbHttps class object.")
        try {
            $svcbHttps = [DnsSvcbHttps]::new($Name, $ZoneName)
        } catch {
            $script:Common.AddLog("Add-DnsServerCustomResourceRecord - DnsSvcbHttps creation failed: $_")
            return ( Write-Error "" -EA Stop )
        }

        # add the TargetName is the value is not a period
        # the TargetName defaults to period (effective record) when the class instance is created
        if ( $HttpsTargetName -ne '.' ) {
            $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Updating TargetName to: $HttpsTargetName")
            $svcbHttps.AddTargetName($HttpsTargetName)
        }

        # create the SvcHttpsParams if there is at least one key provided
        if ( $HttpsMandatory -or $HttpsALPN -or $HttpsNoDefaultALPN -or $HttpsPort -ge 0 -or $HttpsIPv4Hint -or $HttpsIPv6Hint ) {
            # add the SvcParam(s) to the svcbHttp object
            # Do Mandatory last! Mandatory fails if the key does not already exist!

            $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding a SvcParam.")

            # add ALPN
            if ( $HttpsALPN ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding ALPN.")
                try {
                    $svcbHttps.AddALPN($HttpsALPN)
                } catch {
                    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add ALPN: $_")
                    return ( Write-Error "Failed to add ALPN: $_" -EA Stop )
                }
            } elseif ($HttpsMandatory -contains "alpn") {
                return ( Write-Error "Mandatory contains alpn but HttpsALPN was not passed." -EA Stop )
            }

            # add no-default-alpn
            if ( $HttpsNoDefaultALPN.IsPresent ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Set no-default-alpn to true.")
                $svcbHttps.AddNoALPN($true)
            }

            # add Port
            if ( $HttpsPort -ge 0 ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding Port.")
                try {
                    $svcbHttps.AddPort($HttpsPort)
                } catch {
                    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add Port: $_")
                    return ( Write-Error "Failed to add Port: $_" -EA Stop )
                }
            } elseif ($HttpsMandatory -contains "port") {
                return ( Write-Error "Mandatory contains port but no HttpsPort was passed." -EA Stop )
            }

            # add IPv4 hints
            if ( $HttpsIPv4Hint ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding IPv4Hint.")
                try {
                    $svcbHttps.AddIPv4Hint($HttpsIPv4Hint)
                } catch {
                    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add Port: $_")
                    return ( Write-Error "Failed to add IPv4Hint: $_" -EA Stop )
                }
            } elseif ($HttpsMandatory -contains "ipv4hint") {
                return ( Write-Error "Mandatory contains ipv4hint but no HttpsIPv4Hint was passed." -EA Stop )
            }

            # add IPv6 hints
            if ( $HttpsIPv6Hint ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding IPv6Hint.")
                try {
                    $svcbHttps.AddIpv6Hint($HttpsIPv6Hint)
                } catch {
                    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add Port: $_")
                    return ( Write-Error "Failed to add IPv6Hint: $_" -EA Stop )
                }
            } elseif ($HttpsMandatory -contains "ipv6hint") {
                return ( Write-Error "Mandatory contains ipv4hint but no HttpsIPv6Hint was passed." -EA Stop )
            }


            # do Mandatory here at the end or validation might fail
            if ( $HttpsMandatory ) {
                $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Adding Mandatory.")

                try {
                    $svcbHttps.AddMandatory($HttpsMandatory)
                } catch {
                    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add Port: $_")
                    return ( Write-Error "Failed to add Mandatory: $_" -EA Stop )
                }
            }

            $script:Common.AddLog("Add-DnsServerCustomResourceRecord - SvcParam creation complete.")
        }
        #endregion
    } elseif ($HttpsSvcPriority -eq "AliasMode") {
        <#
            AliasMode

            This mode acts like an ANAME or CNAME record, pointing an apex or other RR to a service or HTTPS ServiceMode record.

            https://www.rfc-editor.org/rfc/rfc9460.html#name-aliasmode-2

            "For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist. This indication 
            is advisory: clients encountering this indication MAY ignore it and attempt to connect without the use of SVCB."

            https://www.rfc-editor.org/rfc/rfc9460.html#name-aliasmode

            "In AliasMode, the SVCB record aliases a service to a TargetName. SVCB RRsets SHOULD only have a single RR in AliasMode. 
            If multiple AliasMode RRs are present, clients or recursive resolvers SHOULD pick one at random.

            The primary purpose of AliasMode is to allow aliasing at the zone apex, where CNAME is not allowed (see, for example, 
            [RFC1912], Section 2.4). In AliasMode, the TargetName will be the name of a domain that resolves to SVCB, AAAA, and/or 
            A records. (See Section 6 for aliasing of SVCB-compatible RR types.) Unlike CNAME, AliasMode records do not affect the 
            resolution of other RR types and apply only to a specific service, not an entire domain name.

            The AliasMode TargetName SHOULD NOT be equal to the owner name, as this would result in a loop. In AliasMode, recipients 
            MUST ignore any SvcParams that are present."
        #>

        # create the DnsSvcbHttps class object using RecordName and ZoneName
        $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Create DnsSvcbHttps class object.")
        try {
            $svcbHttps = [DnsSvcbHttps]::new($Name, $ZoneName, $HttpsTargetName)
        } catch {
            $script:Common.AddLog("Add-DnsServerCustomResourceRecord - DnsSvcbHttps creation failed: $_")
            return ( Write-Error "" -EA Stop )
        }

        # add the TargetName
        $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Updating TargetName to: $HttpsTargetName")
        $svcbHttps.AddTargetName($HttpsTargetName)
    } else {
        return ( Write-Error "Invalid SvcPriority. The valid options are: $([DnsSvcbPriority].GetEnumNames() -join ', ') " -EA Stop )
    }

    # get the RecordData hex stream
    $RecordData = $svcbHttps.GetRecordData()
    $script:Common.AddLog("Add-DnsServerCustomResourceRecord - RecordData: $RecordData")

    # create the record
    try {
        if ( $PassThru.IsPresent -or $ReturnRecordData.IsPresent ) {
            $result = Add-DnsServerResourceRecord -ZoneName $ZoneName -Name $Name -Type 65 -RecordData $RecordData -PassThru

            if ( $ReturnRecordData.IsPresent ) {
                return ($result.RecordData.Data)
            } elseif ( $PassThru.IsPresent ) {
                return $result
            }
        } else {
            $result = Add-DnsServerResourceRecord -ZoneName $ZoneName -Name $Name -Type 65 -RecordData $RecordData
        }
    } catch {
        $script:Common.AddLog("Add-DnsServerCustomResourceRecord - Failed to add the record: $_")
        return ( Write-Error "Failed to add the record: $_" -EA Stop )
    }
}

function New-DnsServerCustomSvcbHttpsServiceStruct {
    # simple SVCB HTTP (65) record structure
    $httpsStruc = [PSCustomObject]@{
        PSTypeName        = "DnsSvcbServiceHttpsRR"
        DistinguishedName = ""
        HostName          = ""
        RecordType        = "HTTPS"
        Type              = 65
        RecordClass       = "IN"
        TimeToLive        = [timespan]"1:0:0"
        SvcPriority       = ""
        TargetName        = ""
        SvcParamObj       = [DnsSvcbHttpsSvcParam]::new()
        SvcParam          = ""
        RecordData        = ""
    }

    $TypeData = @{
        TypeName                  = 'DnsSvcbServiceHttpsRR'
        DefaultDisplayPropertySet = 'HostName', 'RecordType', 'Type', 'SvcPriority', 'TargetName', 'SvcParam'
    }

    Update-TypeData @TypeData -EA SilentlyContinue

    return $httpsStruc
}

function New-DnsServerCustomSvcbHttpsAliasStruct {
    # simple SVCB HTTP (65) record structure
    $httpsStruc = [PSCustomObject]@{
        PSTypeName        = "DnsSvcbAliasHttpsRR"
        DistinguishedName = ""
        HostName          = ""
        RecordType        = "HTTPS"
        Type              = 65
        RecordClass       = "IN"
        TimeToLive        = [timespan]"1:0:0"
        SvcPriority       = ""
        TargetName        = ""
        RecordData        = ""
    }

    $TypeData = @{
        TypeName                  = 'DnsSvcbAliasHttpsRR'
        DefaultDisplayPropertySet = 'HostName', 'RecordType', 'Type', 'SvcPriority', 'TargetName'
    }

    Update-TypeData @TypeData -EA SilentlyContinue

    return $httpsStruc
}

function Get-DnsServerCustomResourceRecordHttps {
    [CmdletBinding()]
    param (
        # DNS zone name.
        [Parameter(Mandatory=$true)]
        [string]
        $ZoneName,

        # Resource record name.
        [Parameter()]
        [string]
        $Name = $null
    )

    # $script:Common.AddLog("Get-DnsServerCustomResourceRecord - ")
    $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Begin!")

    # get the SVCB records from DNS
    try {
        $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Getting records and record data.")
       if ( [string]::IsNullOrEmpty( $Name ) ) {
            # get all the SVCB HTTPS (type 65) records
            [array]$RRs = Get-DnsServerResourceRecord -ZoneName $ZoneName -Type 65 -EA Stop
        } else {
            # get one SVCB HTTPS (type 65) records
            [array]$RRs = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $Name -Type 65 -EA Stop
        } 
    } catch {
        return ( Write-Error "$_" -EA Stop )
    }

    $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Found $($RRs.Count) matching records.")

    # populate httpsStruc with the record details
    $list = [List[Object]]::new()
    foreach ($rr in $RRs) {
        $script:Common.AddLog("Get-DnsServerCustomResourceRecord - RecordData: $($rr.RecordData.Data)")

        <#
            SvcPriority ($sp)

            0 = AliasMode
            1 = ServiceMode
        #>
        $sp = [int]"0x$($rr.RecordData.Data.SubString(0,4))"

        $script:Common.AddLog("Get-DnsServerCustomResourceRecord - SvcPriority: $sp")

        if ($sp -eq 0) {
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Processing AliasMode record.")
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Creating an AliasMode struct.")
            $tmpObj = New-DnsServerCustomSvcbHttpsAliasStruct

            #  copy values from rr to tmpObj
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Copying RR data to struct.")
            $tmpObj.DistinguishedName = $rr.DistinguishedName
            $tmpObj.HostName          = $rr.HostName
            $tmpObj.TimeToLive        = $rr.TimeToLive
            $tmpObj.RecordData        = $rr.RecordData.Data

             # get the last of the HTTPS RR data
             $tmpObj.SvcPriority = [DnsSvcbHttpsPriority]$sp
             
             $tn = $script:Common.Convert_DnsHexStrem2DnsName($rr.RecordData.Data.SubString(4))
 
             if ( [string]::IsNullOrEmpty($tn) ) {
                $script:Common.AddLog("Get-DnsServerCustomResourceRecord - TargetName is NULL, translating to '.' (dot).")
                $tmpObj.TargetName = '.'
             } else {
                $script:Common.AddLog("Get-DnsServerCustomResourceRecord - TargetName: $tn")
                 $tmpObj.TargetName = $tn
             }

             $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Completed AliasMode struct:$($tmpObj | Format-List | Out-String)")

        } elseif ($sp -eq 1) {
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Processing ServiceMode record.")
            # get a RR struct
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Creating a ServiceMode struct.")
            $tmpObj = New-DnsServerCustomSvcbHttpsServiceStruct

            #  copy values from rr to tmpObj
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Copying data to struct.")
            $tmpObj.DistinguishedName = $rr.DistinguishedName
            $tmpObj.HostName          = $rr.HostName
            $tmpObj.TimeToLive        = $rr.TimeToLive
            $tmpObj.RecordData        = $rr.RecordData.Data

            # fill in the struct
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Processing the SvcParam data.")
            $tmpObj.SvcParamObj.ImportSvcParamFromRecordData($rr.RecordData.Data)
            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - SvcParam data processed.")

            # add the dig string to SvcParam
            $tmpObj.SvcParam = $tmpObj.SvcParamObj.ToDigString()

            # get the last of the HTTPS RR data
            $tmpObj.SvcPriority = [DnsSvcbHttpsPriority]$sp
            
            $tn = $script:Common.Convert_DnsHexStrem2DnsName($rr.RecordData.Data.SubString(4))

            if ( [string]::IsNullOrEmpty($tn) ) {
                $script:Common.AddLog("Get-DnsServerCustomResourceRecord - TargetName is NULL, translating to '.' (dot).")
                $tmpObj.TargetName = '.'
            } else {
                $script:Common.AddLog("Get-DnsServerCustomResourceRecord - TargetName: $tn")
                $tmpObj.TargetName = $tn
            }

            $script:Common.AddLog("Get-DnsServerCustomResourceRecord - Completed ServiceMode struct:$($tmpObj | Format-List | Out-String)")
        } else {
            $script:Common.NewWarning("DnsServerCustomResourceRecord", "Get-DnsServerCustomResourceRecordHttps", "UNKNOWN_SVCPRIORITY", "Unknown SvcPriority: $sp")
        }

        if ($tmpObj) {
            $list.Add($tmpObj)
        }
        
        Remove-Variable tmpObj -EA SilentlyContinue
    }

    $script:Common.AddLog("Get-DnsServerCustomResourceRecord - End")
    return $list
}