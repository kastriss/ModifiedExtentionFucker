# 1. Paths to scan
$TargetPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\AppData\Local\Temp",
    "C:\Users\Public"
)

# Extensions that should NOT natively contain compiled executable machine code
$NonExeExtensions = @('.png', '.jpg', '.jpeg', '.gif', '.txt', '.cfg', '.ini', '.log', '.dat', '.mp4', '.zip', '.pdf')

Write-Host "[*] Auditing files for extension modifications and extensionless EXEs..." -ForegroundColor Cyan
Write-Host "[*] Checking magic file headers. Please wait...`n" -ForegroundColor Gray

$FoundCount = 0

foreach ($Path in $TargetPaths) {
    if (-not (Test-Path $Path)) { continue }

    # Gathering the files
    $Files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
             Where-Object { $_.Extension.ToLower() -in $NonExeExtensions -or [string]::IsNullOrEmpty($_.Extension) }

    foreach ($File in $Files) {
        try {
            # Safely open file stream and read the first two bytes (Magic Header)
            $Stream = [System.IO.File]::OpenRead($File.FullName)
            $Bytes = New-Object Byte[] 2
            $ReadCount = $Stream.Read($Bytes, 0, 2)
            $Stream.Close()

            if ($ReadCount -eq 2) {
                # Convert bytes to string to check for the 'MZ' executable magic header
                $MagicHeader = [System.Text.Encoding]::ASCII.GetString($Bytes)
                
                if ($MagicHeader -eq "MZ") {
                    $FoundCount++
                    
                    # Determine if it's a spoofed extension or entirely extensionless
                    $DetectionType = if ([string]::IsNullOrEmpty($File.Extension)) { "EXTENSIONLESS EXECUTABLE DETECTED!" } else { "SPOOFED EXECUTABLE DETECTED!" }

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
    Write-Host "[+] Clean! No hidden or extensionless executables found." -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Found $FoundCount executable file(s) disguised or missing extensions." -ForegroundColor Red
}
