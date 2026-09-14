# 1. Paths to scan
$TargetPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\AppData\Local\Temp",
    "C:\Users\Public"
)

# Define known executable extensions.
$KnownExeExtensions = @('.exe', '.dll', '.sys', '.scr', '.msi', '.bat', '.cmd', '.cpl')

Write-Host "[*] Auditing files for extension modifications, random extensions, and extensionless EXEs..." -ForegroundColor Cyan
Write-Host "[*] Checking magic file headers. Please wait...`n" -ForegroundColor Gray

$FoundCount = 0

foreach ($Path in $TargetPaths) {
    if (-not (Test-Path $Path)) { continue }

    # Gathering the files -filters out legitimate executables-
    $Files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
             Where-Object { $_.Extension.ToLower() -notin $KnownExeExtensions }

    foreach ($File in $Files) {
        try {
            # Read the header
            $Stream = [System.IO.File]::OpenRead($File.FullName)
            $Bytes = New-Object Byte[] 2
            $ReadCount = $Stream.Read($Bytes, 0, 2)
            $Stream.Close()

            if ($ReadCount -eq 2) {
                # From bytes to MZ
                $MagicHeader = [System.Text.Encoding]::ASCII.GetString($Bytes)
                
                if ($MagicHeader -eq "MZ") {
                    $FoundCount++
                    
                    # Extentionless or Spoofed...
                    if ([string]::IsNullOrEmpty($File.Extension)) { 
                        $DetectionType = "EXTENSIONLESS EXECUTABLE DETECTED!" 
                    } else { 
                        $DetectionType = "SPOOFED / CUSTOM EXTENSION DETECTED ($($File.Extension.ToUpper()))!" 
                    }

                    # Checking signature
                    $Signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
                    $SigText = if ($Signature.Status -eq "Valid") { "SIGNED (Valid)" } else { "UNSIGNED ($($Signature.Status))" }
                    $SigColor = if ($Signature.Status -eq "Valid") { "Green" } else { "Red" }

                    Write-Host "[!] $DetectionType" -ForegroundColor Yellow
                    Write-Host "    Current Name: $($File.Name)" -ForegroundColor White
                    Write-Host "    Full Path:    $($File.FullName)" -ForegroundColor Gray
                    Write-Host "    Signature:    $SigText" -ForegroundColor $SigColor
                    Write-Host ""
                }
            }
        } catch {
            if ($Stream) { $Stream.Close() }
        }
    }
}

# Credits ( Cause I am the best )
Write-Host "[*] Scan complete." -ForegroundColor Cyan
Write-Host "Made with love by kastris_`n" -ForegroundColor Blue

if ($FoundCount -eq 0) {
    Write-Host "[+] Clean! No hidden, custom, or extensionless executables found." -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Found $FoundCount executable file(s) disguised or missing extensions." -ForegroundColor Red
}
