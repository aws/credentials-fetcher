#!/bin/sh

# Thanks to https://github.com/dotnet/sdk/issues/8742#issuecomment-890559867

DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_CLI_TELEMETRY_OPTOUT

sdkver=$(LC_ALL=C dotnet --version)
fwkver=$(LC_ALL=C dotnet --list-runtimes | \
    LC_ALL=C sed --posix -n '/^Microsoft.NETCore.App \([^ ]*\) .*$/{s//\1/p;q;}')

dotnethome=/usr/lib/dotnet
if [ -d /usr/lib64/dotnet ]; then
   dotnethome=/usr/lib64/dotnet
fi
echo "dotnethome=$dotnethome"

dotnetlib=$dotnethome/shared/Microsoft.NETCore.App/$fwkver
if [ -d /usr/share/dotnet/packs/Microsoft.NETCore.App.Ref/$fwkver/ref/net6.0/ ]; then
   dotnetlib=/usr/share/dotnet/packs/Microsoft.NETCore.App.Ref/$fwkver/ref/net6.0/
fi
echo "dotnetlib=$dotnetlib"

dotnet_cscdll=$dotnethome/sdk/$sdkver/Roslyn/bincore/csc.dll
if [ -f /usr/share/dotnet/sdk/$sdkver/Roslyn/bincore/csc.dll ]; then
   dotnet_cscdll=/usr/share/dotnet/sdk/$sdkver/Roslyn/bincore/csc.dll
fi
echo "dotnet_cscdll=$dotnet_cscdll"

dotnet_csclib='-r:netstandard.dll -r:Microsoft.CSharp.dll -r:System.dll'
for x in "$dotnetlib"/System.*.dll; do
	dotnet_csclib="$dotnet_csclib -r:${x##*/}"
done
echo "dotnet_csclib=$dotnet_csclib"
# add if needed
#dotnet_csclib="$dotnet_csclib -r:Microsoft.Win32.Primitives.dll"

exec dotnet "$dotnet_cscdll" "-lib:$dotnetlib" $dotnet_csclib "$@"

#!/bin/sh

DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_CLI_TELEMETRY_OPTOUT

sdkver=$(LC_ALL=C dotnet --version)
fwkver=$(LC_ALL=C dotnet --list-runtimes | \
    LC_ALL=C sed --posix -n '/^Microsoft.NETCore.App \([^ ]*\) .*$/{s//\1/p;q;}')

exename=$1
case $exename in
(*.exe|*.EXE) ;;
(*)
	echo >&2 "E: $exename is not a .exe file"
	exit 1
	;;
esac

jsonname=${exename%.*}.runtimeconfig.json
printf '%s"%s"%s\n' \
    '{"runtimeOptions":{"framework":{"name":"Microsoft.NETCore.App","version":' \
    "$fwkver" '}}}' >"$jsonname"
