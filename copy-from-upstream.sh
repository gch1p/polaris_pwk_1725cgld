#!/bin/bash

set -e

HOMEKIT="$1"
[ -z "$HOMEKIT" ] && HOMEKIT=$HOME/dev/home

cp -r $HOMEKIT/src/polaris .
git add polaris
git commit -am "sync with upstream"
git push
