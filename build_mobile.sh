#!/usr/bin/env bash
set -e -u -o pipefail # Fail on error

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo "current dir is $dir"
cd $dir

arg=${1:-}

package="github.com/lightningnetwork/lnd/mobile"

ios_dest="$dir/mobile/build/ios/Lndbindings.framework"
echo "Building for iOS ($ios_dest)..."
"$GOPATH/bin/gomobile" bind -target=ios -tags="ios" -v -o "$ios_dest" "$package"

