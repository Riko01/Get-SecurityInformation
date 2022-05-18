<# 
.SYNOPSIS
The script will read computers security information of Defender setup, firewall status and last date of installed hotfixes.

.DESCRIPTION
Scripts reads comupters from input csv file, Active Directory or given computer name and check their status with basic powershell cmdlets for Firewall, last hotfixes and Windows Defender state.
Output of the script is then an updated csv file with the latest information. 

.NOTES
Company: IXTENT s.r.o.
Author: Juraj Harasta
Versions:
2022-02-02 - First version
2022-02-04 - Change of text-connection from ICMP to 135 RPC, and exporting not reachable Computers to csv as well, if they do not exists there yet. Help update.
2022-02-09 - Changed methods using WinRM to methods using RPC and added test for 135 port
2022-03-22 - Adjustment of non existent csv condition, removal of usnused log file, new declaration of hash table for $hostnames


For server run:
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
    For PC run:
        Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online

Import-Module -Name ActiveDirectory

.INPUTS
reportPath - Script will create after first run a csv file that will be used next time as input as well in order not to query Active Directory from computer names
computerName - If input parameter computer name is specified it will query only this computer/s

.OUTPUTS
reportPath - Script will create at the end csv file with gathered information.
failedConnections - If computer is not reachable it will be written into txt file.

.EXAMPLE
Get-SecurityInformation.ps1 -reportPath computers.csv -adFilter *IXTHARA* -logFile .\Get-SecurityInformation.log
Script started 2022-02-02 10:01:25

Connection test to IXTHARASTA2 failed, writing hostname to computers.csv.log
Connection test to IXTPETER failed, writing hostname to computers.csv.log
Connection test to IXTHARASTA successfull, updating information

Hostname    Update              LastHotfix          FW1  FW2  FW3  WinDef
--------    ------              ----------          ---  ---  ---  ------
IXTHARASTA2 2022-02-01 15:06    2022-01-31          TRUE TRUE TRUE TRUE  
IXTPETER    2022-02-01          2022-01-31          TRUE TRUE TRUE TRUE  
IXTHARASTA  2022-02-02 10:01:33 2022-01-31 00:00:00 True True True True  



Execution time: 8.92s
Script finished 2022-02-02 10:01:34
#>

[CmdletBinding()]
#Requires -Modules ActiveDirectory
#Requires -Version 5.1

Param(
	#[Parameter(Mandatory=$true)]
   	[Alias("path")]
    $reportPath = "computers.csv",
    $adFilter = "*IXTH*",
	#[switch]$getListFromAD = $false,
	$logFile = "Get-SecurityInformation.log",
    $computerName = $false,
    $failedConnections = "failedConnections.log"
)

#****************************************************************************************************
# Section for defining parameters,values and variables
#****************************************************************************************************

$global:logFile=$logFile
$delimeter = "`t"
if ($computerName -ne $false) {
    $computerName=$computerName.ToUpper()
}
$hostnames = @()

#******************************************************************************
# Functions
#******************************************************************************
function Write-Log ($msg, 
    [Parameter()]
    [ValidateSet('INFO','ERROR','DEBUG','WARNING','FATAL')]
    [string[]]
    $severity='INFO') 
{
    $date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logRecord = "$date | $severity | $msg"
    Add-Content -Path $global:logFile -Value $logRecord
}

Function FirewallCheck ($computer) {
    Try {
        #$fw1 = Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty Enabled
        $fw1 = netsh -r $computer advfirewall show Domain State | Select-String -Pattern "State\s+(\w+)$" | foreach {$_.Matches.Groups[1].Value}
    } Catch {
        Write-Error "FW1 - Error communicating with $computer"
        Write-Log "FW1 - Error communicating with $computer" -severity ERROR
    }
    Try {
        #$fw2 = Get-NetFirewallProfile -Profile Private | Select-Object -ExpandProperty Enabled
        $fw2 = netsh -r $computer advfirewall show Private State | Select-String -Pattern "State\s+(\w+)$" | foreach {$_.Matches.Groups[1].Value}
    } Catch {
        Write-Error "FW2 - Error communicating with $computer"
        Write-Log "FW2 - Error communicating with $computer" -severity ERROR
    }
    Try {
        #$fw3 = Get-NetFirewallProfile -Profile Public | Select-Object -ExpandProperty Enabled
        $fw3 = netsh -r $computer advfirewall show Public State | Select-String -Pattern "State\s+(\w+)$" | foreach {$_.Matches.Groups[1].Value}
    } Catch {
        Write-Error "FW3 - Error communicating with $computer"
        Write-Log "FW3 - Error communicating with $computer" -severity ERROR
    }
    return $fw1, $fw2, $fw3
}

Function WindowsDefender ($computer) {
    Try {
        #$windowsDefender = Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled
        $windowsDefender = Get-WmiObject -Namespace "root/microsoft/windows/defender" -Query "SELECT * FROM MSFT_MpPreference" -ComputerName $computer | Select-Object -ExpandProperty DisableRealTimeMonitoring
    } Catch {
        Write-Error "Def - Error communicating with $computer"
        Write-Log "Def - Error communicating with $computer" -severity ERROR
    }
    Return $windowsDefender
}

Function WindowsUpdates ($computer) {
    Try {
        $lastHotFixDate=(Get-HotFix -ComputerName $computer | Sort-Object -Property InstalledOn | Select-Object -ExpandProperty InstalledOn -Last 1 -ErrorAction Stop).toString('yyyy-MM-dd')
    } catch [Exception] {
        Write-Error "Upd - Error communicating with $computer, skipping to next"
        Write-Log "Upd - Error communicating with $computer, skipping to next" -severity ERROR
    } 
    return $lastHotFixDate
}

#******************************************************************************
# Main
#******************************************************************************

$script:startTime = get-date 
Write-Host "Script started $($script:startTime.ToString('yyyy-MM-dd HH:mm:ss'))`n"
Write-Log "Script started $($script:startTime.ToString('yyyy-MM-dd HH:mm:ss'))"

if (Test-Path -Path $reportPath) {
    $importCsv = Import-Csv -Path $reportPath -Delimiter "`t"
    $computers = @($importCsv)
    $hostnames = @($computers.Hostname)
}

if (!($adFilter -eq $null)) {
    $hostnames += Get-ADComputer -filter "Name -like `"$adFilter`"" | Select-Object -ExpandProperty Name
}

if (!($computerName -eq $false)) {
    $hostnames = $computerName
}

$hostnames = $hostnames | Select-Object -Unique

Foreach($computer in $hostnames){
    # The follwing test is not possible where ICMP is forbiden.
    #if(Test-Connection -ComputerName $computer -BufferSize 16 -Count 1 -ea 0 -quiet) {
    #
    if((Test-NetConnection -ComputerName $computer -Port 135).TcpTestSucceeded) {
    #if ($true) {
        Write-Host "Connection test to $computer successfull, updating information"
        Write-Log "Connection test to $computer successfull, updating information"
        $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        $windowsUpdateResults = WindowsUpdates $computer
        $windowsFirewallResults = FirewallCheck $computer
        $windowsDefResults = WindowsDefender $computer
                    
        $pcObject = [ordered]@{ 
            Hostname = $computer
            Update = $date
            LastHotfix = $windowsUpdateResults
            FW1 = $windowsFirewallResults[0]
            FW2 = $windowsFirewallResults[1]
            FW3 = $windowsFirewallResults[2]
            WinDef = $windowsDefResults
        }
        $pcObject = New-Object -TypeName PSObject -Property $pcObject                
        
        if ($computers.Length -eq 0) {
            $computers += $pcObject
        } Else {
            $itemIndex = $computers.Hostname.IndexOf($computer)
            if ($itemIndex -eq -1) {
                $computers+=$pcObject
            } else {
                $computers[$itemIndex]=$pcObject
            }
        }
        
    } else {
        Write-Host "Connection test to $computer failed, writing hostname to $failedConnections"
        Write-Log "Connection test to $computer failed, writing hostname to $failedConnections" -severity WARNING
        $computer | Out-File -FilePath "$failedConnections" -Append
        
        $itemIndex = $computers.Hostname.IndexOf($computer)
        if ($itemIndex -eq -1) {
            $pcObject = [ordered]@{ 
                Hostname = $computer
                Update = $null
                LastHotfix = $null
                FW1 = $null
                FW2 = $null
                FW3 = $null
                WinDef = $null
            }
            $pcObject = New-Object -TypeName PSObject -Property $pcObject 
            $computers+=$pcObject
        }
    }
    
}
$computers | Format-Table -Property Hostname,Update,LastHotfix,FW1,FW2,FW3,WinDef
$computers | Export-Csv -Path "$reportPath" -Delimiter $delimeter -NoTypeInformation  -Encoding Unicode

#******************************************************************************
# Statistics
#******************************************************************************

$executionTime = new-timespan $script:StartTime $(get-date)
Write-Host "Execution time: $([math]::Round($executionTime.TotalSeconds,2))s"
Write-Log "Execution time: $([math]::Round($executionTime.TotalSeconds,2))s"

#******************************************************************************
# The END
#******************************************************************************

Write-Host "Script finished $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Script finished $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
