# dump.ps1 - 启动目标 EXE，周期性扫描其内存，dump 出重建的 PE 映像
# 用法: .\dump.ps1 -Exe <exe路径> -Out out -Pesieve .\pe-sieve64.exe -Seconds 45
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$Out = "out",
  [string]$Pesieve = "",
  [int]$Seconds = 45
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace W {
  public static class M {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct MBI {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
  }
}
"@

function Get-Bytes($h, $addr, $len) {
  try { $buf = New-Object byte[] ([int64]$len) } catch { return $null }
  $rd = [IntPtr]::Zero
  if ([W.M]::ReadProcessMemory($h, $addr, $buf, $buf.Length, [ref]$rd)) { return $buf }
  return $null
}

$workdir = Split-Path -Parent $Exe
$proc = Start-Process -FilePath $Exe -WorkingDirectory $workdir -PassThru
$target = $proc.Id
Write-Host "STARTED pid=$target exe=$Exe"
Start-Sleep -Seconds 3

$h = [W.M]::OpenProcess(0x0410, $false, $target)
if ($h -eq [IntPtr]::Zero) {
  Write-Host "OpenProcess FAILED err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  exit 1
}

$seen = @{}
$total = 0
$t0 = Get-Date
$round = 0

while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
  $round++
  if ($proc.HasExited) { Write-Host "process EXITED at round $round code=$($proc.ExitCode)"; break }

  $addr = [IntPtr]::Zero
  while ($true) {
    $mbi = New-Object W.MBI
    $r = [W.M]::VirtualQueryEx($h, $addr, [ref]$mbi, [IntPtr]::Size)
    if ($r -eq 0) { break }
    $base = [int64]$mbi.BaseAddress
    $sz   = [int64]$mbi.RegionSize

    if ($mbi.State -eq 0x1000 -and $sz -ge 65536 -and $mbi.Protect -ne 0x01) {
      $key = "$base/$sz"
      if (-not $seen.ContainsKey($key)) {
        $head = Get-Bytes $h $base 4096
        if ($head) {
          $isMZ = ($head[0] -eq 0x4D -and $head[1] -eq 0x5A)
          $pb   = [int]($mbi.Protect -band 0xFF)
          $isExec = @(0x10,0x20,0x40,0x80,0xE0,0xF0) -contains $pb

          if ($isMZ) {
            $lfa = [BitConverter]::ToInt32($head, 0x3C)
            if ($lfa -gt 0x40 -and $lfa -lt 0x1000 -and $head[$lfa] -eq 0x50 -and $head[$lfa+1] -eq 0x45) {
              $imgSz = [BitConverter]::ToInt32($head, $lfa + 0x50)
              $take = [int64]$imgSz
              if ($take -le 0 -or $take -gt 512MB) { $take = [Math]::Min($sz, 128MB) }
              if ($take -gt $sz) { $take = $sz }
              $data = Get-Bytes $h $base $take
              if ($data) {
                $fn = Join-Path $Out ("mz_{0:x}_base_{1:x}_img_{2:x}.bin" -f $total, $base, $imgSz)
                [IO.File]::WriteAllBytes($fn, $data)
                Write-Host ("DUMP-MZ   {0}  taken={1} region={2} prot=0x{3:x}" -f $fn, $take, $sz, $mbi.Protect)
                $seen[$key] = 1; $total++
              }
            }
          }
          elseif ($isExec -and $sz -ge 1MB) {
            $take = [Math]::Min($sz, 64MB)
            $data = Get-Bytes $h $base $take
            if ($data) {
              $fn = Join-Path $Out ("exec_{0:x}_base_{1:x}_sz_{2:x}.bin" -f $total, $base, $take)
              [IO.File]::WriteAllBytes($fn, $data)
              Write-Host ("DUMP-EXEC {0}  taken={1} region={2} prot=0x{3:x}" -f $fn, $take, $sz, $mbi.Protect)
              $seen[$key] = 1; $total++
            }
          }
        }
      }
    }

    $next = $base + $sz
    if ($next -le $addr.ToInt64()) { break }
    $addr = [IntPtr]$next
    if ($addr.ToInt64() -ge 0x7FFFFFFE0000) { break }
  }

  if ($round -eq 1) {
    try {
      $proc.Refresh()
      $proc.Modules | Select-Object -First 40 | ForEach-Object {
        Write-Host ("MOD {0} base=0x{1:x} size={2}" -f $_.ModuleName, [int64]$_.BaseAddress, $_.ModuleMemorySize)
      }
    } catch { Write-Host "modules read failed: $_" }
  }
  Start-Sleep -Milliseconds 1200
}

if ($Pesieve -and (Test-Path $Pesieve) -and -not $proc.HasExited) {
  $psdir = Join-Path $Out "pesieve"
  New-Item -ItemType Directory -Force -Path $psdir | Out-Null
  Write-Host "== pe-sieve pid $target =="
  & $Pesieve /pid $target /dmode 3 /imp 3 /shellc 0 /dir $psdir 2>&1 |
    Tee-Object -FilePath (Join-Path $Out "pesieve_log.txt") | Select-Object -First 80
  Get-ChildItem -Recurse $psdir -ErrorAction SilentlyContinue | Select-Object FullName,Length | Format-Table -AutoSize
}

Write-Host "TOTAL DUMPS = $total"
[W.M]::CloseHandle($h) | Out-Null
if (-not $proc.HasExited) {
  Stop-Process -Id $target -Force -ErrorAction SilentlyContinue
  Write-Host "killed pid $target"
}
