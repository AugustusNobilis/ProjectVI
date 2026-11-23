$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'build'
foreach ($p in @($here,$out)) {
    if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Build location is a reparse point.'
    }
}
[void][IO.Directory]::CreateDirectory($out)
$x86root = [Environment]::GetFolderPath('ProgramFilesX86')
$vcCandidates = foreach ($base in @((Join-Path $env:ProgramFiles 'Microsoft Visual Studio'),(Join-Path $x86root 'Microsoft Visual Studio'))) {
    if (![IO.Directory]::Exists($base)) { continue }
    foreach ($product in [IO.Directory]::GetDirectories($base)) {
        foreach ($edition in [IO.Directory]::GetDirectories($product)) {
            $tools = Join-Path $edition 'VC\Tools\MSVC'
            if ([IO.Directory]::Exists($tools)) {
                foreach ($v in [IO.Directory]::GetDirectories($tools)) {
                    if ([IO.File]::Exists((Join-Path $v 'bin\Hostx64\x64\cl.exe'))) { $v }
                }
            }
        }
    }
}
$vc = $vcCandidates | Sort-Object { [version]([IO.Path]::GetFileName($_)) } -Descending | Select-Object -First 1
if (!$vc) { throw 'MSVC x64 not found.' }
$kits = Join-Path $x86root 'Windows Kits\10'
$kitDirectory = Get-ChildItem -LiteralPath (Join-Path $kits 'Include') -Directory | Where-Object {
    [IO.File]::Exists((Join-Path $_.FullName 'um\d3d12.h')) -and [IO.File]::Exists((Join-Path $kits ("Lib\" + $_.Name + "\um\x64\kernel32.lib")))
} | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (!$kitDirectory) { throw 'Windows SDK with D3D12 headers not found.' }
$kit = $kitDirectory.Name
$compiler = Join-Path $vc 'bin\Hostx64\x64\cl.exe'
$linker = Join-Path $vc 'bin\Hostx64\x64\link.exe'
$oldInclude=$env:INCLUDE; $oldLib=$env:LIB; $oldCL=$env:CL; $oldLink=$env:LINK; $oldExtra=$env:_CL_
Push-Location -LiteralPath $out
try {
    $env:CL=$null; $env:_CL_=$null; $env:LINK=$null
    $env:INCLUDE = @((Join-Path $vc 'include'),(Join-Path $kitDirectory.FullName 'um'),(Join-Path $kitDirectory.FullName 'shared'),(Join-Path $kitDirectory.FullName 'ucrt'),(Join-Path $kitDirectory.FullName 'winrt')) -join ';'
    $env:LIB = @((Join-Path $vc 'lib\x64'),(Join-Path $kits "Lib\$kit\um\x64"),(Join-Path $kits "Lib\$kit\ucrt\x64")) -join ';'
    & $linker '/NOLOGO' '/DLL' '/NOENTRY' '/NODEFAULTLIB' '/MACHINE:X64' '/BREPRO' '/OUT:CompatRootSignature.dll' ('/DEF:' + (Join-Path $here 'CompatRootSignature.def'))
    if ($LASTEXITCODE -ne 0 -or ![IO.File]::Exists((Join-Path $out 'CompatRootSignature.dll'))) { throw 'Bridge build failed.' }
    & $compiler '/nologo' '/W4' '/WX' '/wd4191' '/MT' '/O2' '/EHsc' '/std:c++17' '/c' (Join-Path $here 'RootSignatureTest.cpp') '/FoRootSignatureTest.obj'
    if ($LASTEXITCODE -ne 0) { throw 'Probe compilation failed.' }
    & $linker '/NOLOGO' '/MACHINE:X64' '/SUBSYSTEM:CONSOLE' '/BREPRO' '/OUT:RootSignatureTest.exe' 'RootSignatureTest.obj' 'kernel32.lib'
    if ($LASTEXITCODE -ne 0) { throw 'Probe linking failed.' }
    & (Join-Path $out 'RootSignatureTest.exe') (Join-Path $out 'CompatRootSignature.dll')
    if ($LASTEXITCODE -ne 0) { throw ("Desktop API self-test failed: " + $LASTEXITCODE) }
    $memory = Join-Path (Split-Path -Parent $here) 'memory'
    foreach ($sourceName in @('CpuPageWindow', 'CpuPageWindowTest')) {
        & $compiler '/nologo' '/W4' '/WX' '/MT' '/O2' '/EHsc' '/std:c++20' '/DWIN32_LEAN_AND_MEAN' '/DNOMINMAX' '/c' (Join-Path $memory ($sourceName + '.cpp')) ('/Fo' + $sourceName + '.obj')
        if ($LASTEXITCODE -ne 0) { throw ('Memory test compilation failed: ' + $sourceName) }
    }
    & $linker '/NOLOGO' '/MACHINE:X64' '/SUBSYSTEM:CONSOLE' '/BREPRO' '/OUT:CpuPageWindowTest.exe' 'CpuPageWindow.obj' 'CpuPageWindowTest.obj' 'onecore.lib' 'kernel32.lib'
    if ($LASTEXITCODE -ne 0) { throw 'Memory test linking failed.' }
    & (Join-Path $out 'CpuPageWindowTest.exe')
    if ($LASTEXITCODE -ne 0) { throw ('Memory test failed: ' + $LASTEXITCODE) }
} finally {
    Pop-Location
    $env:INCLUDE=$oldInclude; $env:LIB=$oldLib; $env:CL=$oldCL; $env:_CL_=$oldExtra; $env:LINK=$oldLink
}
