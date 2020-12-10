$installationPath = vswhere.exe -latest -property installationPath
if (-not $installationPath -or -not (test-path "$installationPath\VC\Auxiliary\Build\vcvars64.bat")) {
  throw "vcvars64.bat file not found"
}
& "${env:COMSPEC}" /s /c "`"$installationPath\VC\Auxiliary\Build\vcvars64.bat`" > nul 2>&1 && set" | . { process {
  if ($_ -match '^([^=]+)=(.*)') {
    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
  }
}}