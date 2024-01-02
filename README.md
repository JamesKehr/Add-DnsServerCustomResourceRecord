# DnsServerCustomResourceRecord
Adds DNS resource records (RR) to Windows DNS Server that are not natively supported by the Windows UI, dnscmd, or the DnsServer PowerShell module.

Windows DNS Server (DNS) has an option to add custom RRs by providing the RR type and a hex stream of the record data. The DnsServerCustomResourceRecord project legerages this capability to make adding custom RR types easier.

Some custom RRs created by this project may appear as type UNKNOWN without parsed record data in Windows DNS Server manager, dnscmd, and native PowerShell. The DnsServerCustomResourceRecord cmdlets should be used to add, view, and change these custom RRs until native support is added to Windows DNS Server.

Wiki: https://github.com/JamesKehr/DnsServerCustomResourceRecord/wiki
Known Issues: https://github.com/JamesKehr/DnsServerCustomResourceRecord/issues

## Supported RR Types

- HTTPS (type 65) - [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html "RFC 9460 - Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)") - Both AliasMode and ServiceMode.

## Planned RR Types

- dohpath for Discovery of Designated Resolvers (DDR) - [RFC 9461](https://www.rfc-editor.org/rfc/rfc9461.html "RFC 9461 - Service Binding Mapping for DNS Servers") and [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462.html "RFC 9462 - Discovery of Designated Resolvers") - This is an extension to the HTTPS RR defined by RFC 9460.
- NAPTR - [RFC 2915](https://www.rfc-editor.org/rfc/rfc2915.html "RFC-2915 - The Naming Authority Pointer (NAPTR) DNS Resource Record") - Adding NATPR is natively supported by dnscmd.exe. Adding PowerShell support is currently a low priority task.

You can request additional RR types by submitting an Issue. Or write the code and submit a PR.

Please include the RFC and a public facing example of a working RR. This helps speed up development greatly.

RRs that are currently in draft, such as the ech and ohttp SvcParam keys for the HTTPS RR, will be considered lowest priority.

# Support

|**NOTE**|
|----------------|
|**These scripts are not an officially supported Microsoft product!**|

This is currently a community driven OSS project. All support queries must be submitted as an Issue in this repository. Do not call Microsoft support about these scripts and any associated module.

The scripts, module, and code come AS-IS with no warranty or guarantees. The scripts are well tested and should not cause any issues, but you must use them at your own risk. See [LICENSE](../main/LICENSE) for more details.

## Versioning


| Label | Definition |
|-------|------------|
| :x: | No support. Related issues will be closed as unsupported. |
| ⚠️  | Limited support and not actively tested. Issues will be addressed at the discretion of the community. |
| :white_check_mark: | Supported. These issues will take priority. |

|Windows Server| Supported |
|--------------|-----------|
| 2008 [R2] | :x: |
| 2012 [R2] | :x: |
| 2016      | ⚠️ |
| 2019      | :white_check_mark: |
| 2022      | :white_check_mark: |

| PowerShell | Supported |
|------------|-----------|
| 1 | :x: |
| 2 | :x: |
| 3 | :x: |
| 4 | :x: |
| 5 | :x: |
| 5.1 | :white_check_mark: |
| 6 | :x: |
| 7.1 | ⚠️ |
| 7.2 | ⚠️ |
| 7.3 | ⚠️ |
| 7.4 | :white_check_mark: |
| 8 | ⚠️ |
