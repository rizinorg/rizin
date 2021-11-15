$name=$args[0]
$bits=$args[1]
$end=$args.Length
$meson_options=$args[2..$end]
$scriptpath=$PSScriptRoot
$builddir=$(Join-Path -Path $env:TEMP -ChildPath "build-win-installer-$name-$bits")
$installdir=$(Join-Path -Path $env:TEMP -ChildPath "rizin-win-installer-$name-$bits")

pushd $PSScriptRoot\..\..

$version=$(python sys\version.py)
echo $version
echo $builddir
echo $installdir

$env:Path += ";$env:ProgramFiles (x86)\Microsoft Visual Studio\Installer"
$env:Path += ";$env:ProgramFiles\7-Zip"
$env:Path += ";$env:ProgramFiles (x86)\Inno Setup 6"

dist\windows\vsdevenv.ps1 $bits

meson --buildtype=release --prefix=$installdir $builddir $meson_options
ninja -C $builddir -j1
ninja -C $builddir install
7z a dist\windows\Output\rizin-$name-$version.zip $installdir
iscc dist\windows\rizin.iss /DRizinLocation=$installdir\* /DLicenseLocation=$PWD\COPYING.LESSER /DMyAppVersion=$version

rm -r $builddir
rm -r $installdir

popd
