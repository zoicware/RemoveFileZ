#Requires -RunAsAdministrator
function Remove-FileZ {


    <#
        .SYNOPSIS
        Remove file or directory with trusted installer privileges

        .DESCRIPTION
        This will attempt to remove a file or directory using Trusted Installer privileges by taking ownership, removing file attributes, and killing any processes using the file/folder.

        .PARAMETER Path
        Path to file or directory, accepts wildcards.

        .PARAMETER Recurse
        Recurse through directory.

        .EXAMPLE
        Remove-FileZ -Path "C:\Windows\Speech" -Recurse
        # Delete Speech App folder

        .EXAMPLE
        Remove-FileZ -Path "C:\Windows\Speech" -Recurse *>$null
        # Delete Speech App folder with no output

        .EXAMPLE
        Remove-FileZ -Path "C:\Windows\Speech\*" -Recurse 
        # Delete all files/folders inside of speech folder but keep directory

        .LINK
       #github repo

        .NOTES
        Author: Zoic
        Twitter: https://twitter.com/1zoic
        GitHub: https://github.com/zoicware
        PSGallery: 
    #>



    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )



    function DownloadHandleApp {
        $Path = "$env:ProgramData\Handle"
        if (!(Test-path $Path)) {
            $ProgressPreference = 'SilentlyContinue'
            $ZipFile = 'Handle.zip'
            $ZipFilePath = "$Path\$ZipFile"
            $Uri = "https://download.sysinternals.com/files/$ZipFile"
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
                Invoke-RestMethod -Method Get -Uri $Uri -OutFile $ZipFilePath -ErrorAction Stop
                Expand-Archive -Path $ZipFilePath -DestinationPath $Path -Force -ErrorAction Stop
                Remove-Item -Path $ZipFilePath -ErrorAction SilentlyContinue
            }
            catch {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                Throw "Failed to download dependency: handle.exe from: $Uri"
            }
        }

    }








    #run powershell as trusted installer credit : https://github.com/AveYo/LeanAndMean
    #added -wait to prevent script from continuing too fast
    function RunAsTI($cmd, $arg) {
        $id = 'RunAsTI'; $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V = ''; 'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $($V, $code) -type 7 -force -ea 0
        Start-Process powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
    } # lean & mean snippet by AveYo, 2022.01.28


   

    #make sure file or folder exists
    try {
        #check if wildcard was passed 
        if ($Path -match '\*' -or $Path -match '\?') {
            $hasWildCard = $true
        }
        else {
            $hasWildCard = $false
            $type = Get-Item -Path $Path -Force -ErrorAction Stop
        }

    
        if ($type.Attributes -like '*Directory*' -or $hasWildCard) {
            #if path is a file set dir
            $dir = Split-Path $Path
            #check dir for wildcard passed
            Get-Item -Path $dir -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Error 'File or Directory NOT Found!'
        return 
    }

    #set path to global so that other powershell windows can use it
    $Global:Path = $Path
    #try to take ownership
    if ($hasWildCard) {
        #put all code in command for trusted installer to avoid lots of powershell sessions
        $command = @"
`$files = Get-ChildItem -Path "`'$Path`'" -File -Force 
        foreach(`$file in `$files){
                `$filepath = `$file.FullName
                takeown /f `$filepath 
                icacls `$filepath /grant administrators:F /t   
        }
        `$dirs = Get-ChildItem -Path "`'$Path`'" -Directory -Force
        foreach(`$dir in `$dirs){
            `$dirpath = `$dir.FullName
            takeown /f `$dirpath /r /d Y 
            icacls `$dirpath /grant administrators:F /t  
        }

"@
        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"  
    }
    else {

        if ($type.Attributes -like '*Directory*') {
            #recurse if path is directory
            RunAsTI cmd "/c takeown /f `'$Path`' /r /d Y && icacls `'$Path`' /grant administrators:F /t"  
        }
        else {
            RunAsTI cmd "/c takeown /f `'$Path`' && icacls `'$Path`' /grant administrators:F /t"  
        }
    }
    
    
    
    
    
    #remove read-only attribute
    if ($hasWildCard) {
        $command = @"
        `$files = Get-ChildItem -Path "`'$Path`'" -File -Force -Exclude 'desktop.ini' 
        foreach(`$file in `$files){
            `$file.Attributes = 'Normal' 
        }
        `$dirs = Get-ChildItem -Path "`'$Path`'" -Directory -Force
        foreach(`$dir in `$dirs){
             `$dir.Attributes = 'Directory' 
        }

"@
        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command" 
    }
    else {
        if ($Recurse) {
            #script block for runasti
            $command = @"
        `$files = Get-ChildItem -Path `'$Path`' -File -Recurse -Force -Exclude 'desktop.ini' 
        foreach (`$file in `$files) {
            `$file.Attributes = 'Normal'
        }
        `$dirs = Get-ChildItem -Path `'$Path`' -Directory -Recurse -Force 
        foreach (`$dir in `$dirs) {
            `$dir.Attributes = 'Directory'
        }
"@
            #reset all attributes with trusted installer
            RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"   

        }
        else {
            #get single file
            $command = @"
            `$file = Get-Item -Path `'$Path`' -Force
            `$file.Attributes = 'Normal'
"@
            #remove file attributes as trusted installer
            RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"    
        }
    }
        
    
    
    
    #create error txt file
    New-Item "$env:ProgramData\error.txt" -ItemType File -Force | Out-Null

    #try to remove with trusted installer
    if ($Recurse -or $hasWildCard) {
        $command = @"
    Remove-Item -Path `'$Path`' -Recurse -Force
foreach(`$err in `$Error){
    if (`$err.Exception -like '*being used by another process*'){
        Add-Content "`$env:ProgramData\error.txt" -Value `$err.Exception -Force
    }
} 
"@
            
        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"  
        
    }
    else {
        $command = @"
       Remove-Item -Path `'$Path`' -Force
    foreach(`$err in `$Error){
    if (`$err.Exception -like '*being used by another process*'){
        Add-Content "`$env:ProgramData\error.txt" -Value `$err.Exception -Force
    }
} 
"@
        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"  
    }

    Start-Sleep 2
    #get errors for files in use
    $errors = Get-Content "$env:ProgramData\error.txt" -Force | Select-String 'System.IO.IOException:' 

    if ($errors -ne $null) {
        #extract file paths from errors
        $openFiles = @()
        foreach ($line in $errors) {
            ($line -match "'(.*)'") | Out-Null
            $openFiles += $matches[1]  
        }
        #download handle app from sys internals to get which process is using the file
        DownloadHandleApp
        $handlePath = "$env:ProgramData\Handle\handle.exe"
        #run handle
        if ($type.Attributes -eq 'Directory') {
            $output = & $handlePath $Path -accepteula
        }
        else {
            $output = & $handlePath $dir -accepteula
        }

        foreach ($line in $output) {
            if ($line -like '*pid:*') {
                foreach ($file in $openFiles) {
                    #remove quotes
                    $file = $file -replace "'" , ' '
                    #check the path from error file with handle output
                    if ($line -like "*$file*") {
                        #get the pid and try to stop with trusted installer
                        ($line -match 'pid:\s+(\d+)') | Out-Null
                        $procID = $matches[1]
                        $command = "Stop-Process -id $procID -Force"
                        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command" 
                      
                        #now try to remove file
                        $command = "Remove-Item -Path $file -Force"
                        RunAsTI powershell "-NoLogo -WindowStyle Hidden -Command $command"
                    }
                }
            }
        }

    }

    #cleanup error file
    Remove-Item -Path "$env:ProgramData\error.txt" -Force -ErrorAction SilentlyContinue

    Start-Sleep 2
    #check that file / folder is deleted
    Write-Host 'Removed File/Folder ' -NoNewline
    $files = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue
    if ($files -eq $null) {
        Write-Host '[SUCCESS]' -ForegroundColor Green
    }
    else {
        #write the names of files not deleted
        Write-Host '[FAIL]' -ForegroundColor Red
        Write-Host '----- File Names -----'
        foreach ($file in $files) {
            Write-Host $file.Name -ForegroundColor Red
        }
    }
   

}
Export-ModuleMember -Function Remove-FileZ 

