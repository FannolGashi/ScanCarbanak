$TEMP_UserProfile = (Get-Item Env:\USERPROFILE).Value
$UserProfile = "$TEMP_UserProfile\Desktop\Carbanak_Files.txt"
Function Scan-Carbanak{
<#
.Synopsis
   Scan one or more computers for Carbanak malware
.DESCRIPTION
   This is a simple tool that you can scan one or more computers if they contain anything about Carbanak malware based on a KasperSky white paper
   For more info please read it on: 
   KrebsOnSecurity: http://krebsonsecurity.com/wp-content/uploads/2015/02/Carbanak_APT_eng.pdf
   NYTimes: http://www.nytimes.com/2015/02/15/world/bank-hackers-steal-millions-via-malware.html?partner=socialflow&smid=tw-nytimes&_r=1
.PARAMETER ComputerName
Specify one or more computers to scan
.PARAMETER ErrorPath
Specify the ErrorPath where you want to save findings. Default is: %Username%\Desktop\Carbanak_Files.txt
.EXAMPLE
   Get-Content AllComputers.txt | Carbanak-Scan
.EXAMPLE
   Carbanak-Scan -ComputerName (Get-Content AllComputers.txt)
.EXAMPLE
   Import-CSV D:\AllComputers.csv | Foreach-object {Carbanak-Scan -ComputerName $_.Machine}
.NOTES
   Windows PowerShell 3.0 is required in order to scan with this file.

   If you are infected, you should Immediately delete these files (See: Test-Path below) and also scan with an AntiVirus (ex: KasperSky Internet Security).
#>
    [CmdletBinding(SupportsShouldProcess=$true, 
                  PositionalBinding=$false)]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()] 
        [String[]]$ComputerName,

        [String]$ErrorPath = $UserProfile
    ) #param

    Begin
    {} #begin
    Process
    {
        foreach($comp in $ComputerName){
            if(CheckOnline $comp){
                $path1 = Test-Path -Path "\\$comp\c$\Documents and settings\All users\application data\mozilla\*.bin"
                $path2 = Test-Path -Path "\\$comp\c$\Windows\System32\com\svchost.exe"
                $path3 = Test-Path -Path "\\$comp\c$\ProgramData\mozilla\*.bin"
                $path4 = Test-Path -Path "\\$comp\c$\Windows\paexec*"
                $path5 = Test-Path -Path "\\$comp\c$\Windows\Syswow64\com\svchost.exe"

                    if($path1 -or $path2 -or $path3 -or $path4 -or $path5){
                        Write-Host "$Comp may be infected" -ForegroundColor Red
                        "$Comp" | Out-File $ErrorPath -Append
                        if($path1){
                            Remove-Item -Path "\\$comp\c$\Documents and settings\All users\application data\mozilla\*.bin" -Force -Verbose
                        }
                        if($path2){
                            Remove-Item -Path "\\$comp\c$\Windows\System32\com\svchost.exe" -Force -Verbose
                        }
                        if($path3){
                            Remove-Item -Path "\\$comp\c$\ProgramData\mozilla\*.bin" -Force -Verbose
                        }
                        if($path4){
                            Remove-Item -Path "\\$comp\c$\Windows\paexec*" -Force -Verbose
                        }
                        if($path5){
                            Remove-Item -Path "\\$comp\c$\Windows\Syswow64\com\svchost.exe" -Force -Verbose
                        }
                    } #if
                    else{
                        Write-Host "$Comp is Clean" -ForegroundColor Green
                    } #else
            } #if
            else{
                Write-Output "$Comp >> OFFLINE" | Out-File "$TEMP_UserProfile\Desktop\Computers_TimedOut.txt" -Append
            } #else
        } #foreach
    } #process
    End
    {} #end
} #function

Function CheckOnline{

    param([String]$ComputerName)

    foreach ($comp in $ComputerName){
        $status = Test-Connection -ComputerName $comp -Quiet
    }
    return $status
}