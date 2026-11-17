param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [Parameter(Mandatory = $true)][string]$SymbolName
)

$ErrorActionPreference = 'Stop'

$bytes = [System.IO.File]::ReadAllBytes($InputFile)
$builder = New-Object System.Text.StringBuilder
[void]$builder.AppendLine('// generated from ' + [System.IO.Path]::GetFileName($InputFile))
[void]$builder.AppendLine('#include <cstddef>')
[void]$builder.AppendLine('')
[void]$builder.AppendLine("extern `"C`" const unsigned char $SymbolName[] = {")

for ($i = 0; $i -lt $bytes.Length; $i += 16) {
    $line = '    '
    $end = [Math]::Min($i + 16, $bytes.Length)
    for ($j = $i; $j -lt $end; $j++) {
        $line += ('0x{0:x2}, ' -f $bytes[$j])
    }
    [void]$builder.AppendLine($line)
}

[void]$builder.AppendLine('};')
[void]$builder.AppendLine("extern `"C`" const std::size_t $($SymbolName)_size = $($bytes.Length);")

$directory = [System.IO.Path]::GetDirectoryName($OutputFile)
if (![string]::IsNullOrEmpty($directory)) {
    [void][System.IO.Directory]::CreateDirectory($directory)
}
[System.IO.File]::WriteAllText($OutputFile, $builder.ToString())
Write-Host "embedded $($bytes.Length) bytes into $OutputFile"
