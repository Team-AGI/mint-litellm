# MINT 단말 설치 묶음: 이 파일을 실행하면 설치된다. 관리자 권한은 한 번만 쓴다.
# 사용: install.cmd [install|uninstall|status] [-UserLevel] [-DryRun]
param(
    [ValidateSet('install', 'uninstall', 'status')][string]$Action = 'install',
    [switch]$UserLevel,
    [switch]$DryRun,
    # 아래 셋은 관리자 권한으로 다시 부를 때만 쓴다(부른 사람의 계정과 결과 파일).
    [string]$Account = $env:USERNAME,
    [string]$AccountHome = $env:USERPROFILE,
    [string]$ResultFile
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Python 3.9 이상을 찾는다. 스토어 안내용 가짜 python.exe는 실행해 보면 걸러진다.
function Find-Python {
    $probe = "import sys; print(sys.executable if sys.version_info >= (3, 9) else '')"
    foreach ($candidate in @(@('python'), @('py', '-3'))) {
        $command = Get-Command $candidate[0] -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $command) { continue }
        $extra = @($candidate | Select-Object -Skip 1)
        try {
            $found = & $command.Source @extra -c $probe 2>$null
            if ($LASTEXITCODE -eq 0 -and $found) { return [string]$found }
        } catch {
            continue
        }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host 'Python 3.9 이상이 필요합니다.'
    exit 2
}

$arguments = @('-I', '-B', (Join-Path $here 'mint_kit.py'), $Action, '--user', $Account, '--home', $AccountHome)
if ($DryRun) { $arguments += '--dry-run' }

function Invoke-Kit([string[]]$More) {
    # 파이썬이 표준 오류로 알리는 안내를 오류로 취급하지 않는다.
    $ErrorActionPreference = 'Continue'
    if ($ResultFile) {
        # 관리자 창은 끝나면 닫히므로 출력을 파일에 남겨 부른 쪽이 보여 준다.
        & $python @arguments @More *>&1 | Out-File -FilePath $ResultFile -Encoding utf8
    } else {
        & $python @arguments @More | Out-Host
    }
    return $LASTEXITCODE
}

$administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($UserLevel) { exit (Invoke-Kit @('--user-level')) }
if ($administrator -or $DryRun) { exit (Invoke-Kit @()) }

# 관리자가 아니면 확인 창으로 한 번 관리자 권한을 요청한다. 거절하면 사용자 수준으로 설치한다
# (MINT에는 「관리되지 않음」으로 보고된다).
$result = Join-Path ([IO.Path]::GetTempPath()) ('mint-kit-' + [Guid]::NewGuid().ToString('N') + '.txt')
$again = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), $Action,
    '-Account', ('"' + $Account + '"'), '-AccountHome', ('"' + $AccountHome + '"'),
    '-ResultFile', ('"' + $result + '"'))
$process = $null
try {
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $again `
        -Verb RunAs -Wait -PassThru
} catch {
    $process = $null
}
if ($process) {
    if (Test-Path -LiteralPath $result) {
        Get-Content -LiteralPath $result -Encoding UTF8
        Remove-Item -LiteralPath $result -Force
    }
    exit $process.ExitCode
}
Write-Host '관리자 권한을 얻을 수 없어 사용자 수준으로 설치합니다.'
exit (Invoke-Kit @('--user-level'))
