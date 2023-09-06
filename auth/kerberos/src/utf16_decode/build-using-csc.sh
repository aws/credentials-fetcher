#!/bin/sh

# Thanks to https://github.com/dotnet/sdk/issues/8742#issuecomment-890559867

DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_CLI_TELEMETRY_OPTOUT
PATH=~/.dotnet:$PATH

sdkver=$(LC_ALL=C dotnet --version)
fwkver=$(LC_ALL=C dotnet --list-runtimes | \
    LC_ALL=C sed --posix -n '/^Microsoft.NETCore.App \([^ ]*\) .*$/{s//\1/p;q;}')

# dotnet-sdk-5.0 installed via .deb package
dotnethome=/usr/share/dotnet
#dotnethome=/home/ec2-user/.dotnet
dotnetlib=$dotnethome/shared/Microsoft.NETCore.App/$fwkver
dotnet_cscdll=$dotnethome/sdk/$sdkver/Roslyn/bincore/csc.dll
dotnet_csclib='-r:netstandard.dll -r:Microsoft.CSharp.dll -r:System.dll'
for x in "$dotnetlib"/System.*.dll; do
	dotnet_csclib="$dotnet_csclib -r:${x##*/}"
done
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
