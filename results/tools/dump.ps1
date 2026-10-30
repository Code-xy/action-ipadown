# dump.ps1 - 启动目标 EXE，扫描内存 dump 重建的 PE 映像 + 抓运行时释放的模块/temp 文件
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$Out = "out",
  [string]$Pesieve = "",
  [int]$Seconds = 90
)
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$modsDir = Join-Path $Out "mods"
New-Item -ItemType Directory -Force -Path $modsDir | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Dumper {
  [StructLayout(LayoutKind.Sequential)]
  public struct MBI {
    public IntPtr Base; public IntPtr AllocBase; public uint AllocProt;
    public IntPtr Size; public uint State; public uint Protect; public uint Type;
  }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int a, bool i, int p);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, int s, out IntPtr r);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, IntPtr l);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  static IntPtr H = IntPtr.Zero;
  static HashSet<string> seen = new HashSet<string>();
  public static void Reset() { seen.Clear(); }
  public static bool Open(int pid) {
    H = OpenProcess(0x1F0FFF, false, pid);
    if (H == IntPtr.Zero) H = OpenProcess(0x0418, false, pid);
    return H != IntPtr.Zero;
  }
  public static void Close() { if (H != IntPtr.Zero) { CloseHandle(H); H = IntPtr.Zero; } }
  static byte[] Read(long addr, int len) {
    if (len <= 0) return null;
    try {
      byte[] b = new byte[len]; IntPtr rd;
      if (ReadProcessMemory(H, new IntPtr(addr), b, len, out rd)) return b;
    } catch {}
    return null;
  }
  public static string DumpRegion(long addr, long size, string path, int maxBytes) {
    int take = (int)Math.Min(size, (long)maxBytes);
    if (take <= 0) return null;
    byte[] d = Read(addr, take);
    if (d == null) return null;
    try { File.WriteAllBytes(path, d); } catch { return null; }
    return path + " (size=" + take + ")";
  }
  public static string Scan(string outDir, int maxSingle) {
    if (H == IntPtr.Zero) return "handle not open";
    var sb = new System.Text.StringBuilder();
    long addr = 0;
    int found = 0;
    while (true) {
      MBI m;
      IntPtr q;
      try { q = VirtualQueryEx(H, new IntPtr(addr), out m, (IntPtr)Marshal.SizeOf(typeof(MBI))); }
      catch { break; }
      if (q == IntPtr.Zero) break;
      long sz = m.Size.ToInt64();
      if (sz <= 0) break;
      if (m.State == 0x1000 && sz >= 0x10000) {
        string key = addr.ToString("x") + "/" + sz.ToString("x");
        if (!seen.Contains(key)) {
          byte[] head = Read(addr, 4096);
          if (head != null) {
            bool isMZ = (head[0] == 0x4D && head[1] == 0x5A);
            uint pb = m.Protect & 0xFF;
            bool exec = (pb == 0x10 || pb == 0x20 || pb == 0x40 || pb == 0x80 || pb == 0xE0);
            if (isMZ) {
              int lfa = BitConverter.ToInt32(head, 0x3C);
              if (lfa > 0x40 && lfa < 0x1000 && head[lfa] == 0x50 && head[lfa + 1] == 0x45) {
                int imgSz = BitConverter.ToInt32(head, lfa + 0x50);
                long take = (imgSz > 0 && imgSz <= sz) ? imgSz : Math.Min(sz, (long)maxSingle);
                string fn = Path.Combine(outDir, "mz_" + found.ToString("d2") + "_" + addr.ToString("x") + "_img" + imgSz.ToString("x") + ".bin");
                string r = DumpRegion(addr, take, fn, maxSingle);
                if (r != null) { sb.AppendLine("DUMP-MZ   " + r + " region=" + sz + " prot=0x" + m.Protect.ToString("x")); found++; }
                seen.Add(key);
              }
            } else if (exec && sz >= (1L << 20)) {
              string fn = Path.Combine(outDir, "exec_" + found.ToString("d2") + "_" + addr.ToString("x") + ".bin");
              string r = DumpRegion(addr, Math.Min(sz, (long)maxSingle), fn, maxSingle);
              if (r != null) { sb.AppendLine("DUMP-EXEC " + r + " region=" + sz + " prot=0x" + m.Protect.ToString("x")); found++; }
              seen.Add(key);
            }
          }
        }
      }
      long next = addr + sz;
      if (next <= addr) break;
      addr = next;
      if (addr >= 0x7FFF00000000L) break;
    }
    sb.AppendLine("scan done, new dumps=" + found);
    return sb.ToString();
  }
}
"@

$workdir = Split-Path -Parent (Resolve-Path $Exe).Path
$tempRoot = $env:TEMP
$dirsBefore = @(Get-ChildItem -LiteralPath $tempRoot -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
$proc = Start-Process -FilePath $Exe -WorkingDirectory $workdir -PassThru
$target = $proc.Id
Write-Host "STARTED pid=$target exe=$Exe temp=$tempRoot"
Start-Sleep -Seconds 3
if (-not [Dumper]::Open($target)) {
  Write-Host ("OpenProcess FAILED err=" + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  exit 1
}
[Dumper]::Reset()

$modSeen = @{}
$fileLog = Join-Path $Out "modules.txt"
$scanLog = Join-Path $Out "scan.log"
$t0 = Get-Date
$round = 0
while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
  $round++
  if ($proc.HasExited) { Write-Host "process EXITED round=$round code=$($proc.ExitCode)"; break }
  $r = [Dumper]::Scan($Out, 67108864)
  $r | Out-File $scanLog -Append
  Write-Host ("-- round {0}: {1}" -f $round, ($r.Trim() -replace "`r?`n", " | "))

  # 非系统模块: 拷文件 + dump 内存
  try {
    $proc.Refresh()
    foreach ($m in $proc.Modules) {
      $fn = $m.FileName
      if (-not $fn) { continue }
      if ($fn -like 'C:\Windows\*') { continue }
      $key = "file:$fn"
      if ($modSeen.ContainsKey($key)) { continue }
      $modSeen[$key] = 1
      $name = [IO.Path]::GetFileName($fn)
      "MOD-FILE  $fn  base=0x$('{0:x}' -f [int64]$m.BaseAddress)  memsize=$($m.ModuleMemorySize)" | Out-File $fileLog -Append
      try { Copy-Item -LiteralPath $fn -Destination (Join-Path $modsDir $name) -Force -ErrorAction Stop }
      catch { try { [IO.File]::WriteAllBytes((Join-Path $modsDir $name), [IO.File]::ReadAllBytes($fn)) } catch { "  file copy failed: $_" | Out-File $fileLog -Append } }
      $md = Join-Path $modsDir ("mem_" + $name + ".bin")
      $rr = [Dumper]::DumpRegion([int64]$m.BaseAddress, [int64]$m.ModuleMemorySize, $md, 67108864)
      if ($rr) { "MOD-MEM   $rr" | Out-File $fileLog -Append }
    }
  } catch { "modules enum failed: $_" | Out-File $fileLog -Append }

  # 新出现的 temp 目录: 全部拷回
  try {
    foreach ($d in (Get-ChildItem -LiteralPath $tempRoot -Directory -ErrorAction SilentlyContinue)) {
      if ($dirsBefore -contains $d.Name) { continue }
      $dst = Join-Path $modsDir ("tmp_" + $d.Name)
      if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Force -Path $dst | Out-Null }
      foreach ($f in (Get-ChildItem -LiteralPath $d.FullName -File -ErrorAction SilentlyContinue)) {
        $o = Join-Path $dst $f.Name
        if (Test-Path $o) { continue }
        try { [IO.File]::WriteAllBytes($o, [IO.File]::ReadAllBytes($f.FullName)); "TMP-FILE  $($f.FullName) -> $o size=$($f.Length)" | Out-File $fileLog -Append }
        catch { "  tmp copy failed $($f.FullName): $_" | Out-File $fileLog -Append }
      }
    }
  } catch { "temp scan failed: $_" | Out-File $fileLog -Append }

  Start-Sleep -Milliseconds 1500
}

if ($Pesieve -and (Test-Path $Pesieve) -and -not $proc.HasExited) {
  $psdir = Join-Path $Out "pesieve"
  New-Item -ItemType Directory -Force -Path $psdir | Out-Null
  Write-Host "== pe-sieve pid $target =="
  & $Pesieve /pid $target /dmode 3 /imp 3 /shellc 0 /dir $psdir *>&1 | Tee-Object -FilePath (Join-Path $Out "pesieve_log.txt") | Select-Object -First 40
}
[Dumper]::Close()
if (-not $proc.HasExited) { Stop-Process -Id $target -Force -ErrorAction SilentlyContinue; Write-Host "killed pid $target" }
Write-Host ("dumps: " + (Get-ChildItem -Recurse $Out -File | Measure-Object).Count + " files")
