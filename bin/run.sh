#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../src
while true; do
    RESTART=
    ./server.js
    if [ ! "$?" -eq 0 ]; then
        /bin/mv log crash.log.`date +%s`
        RESTART=1
    fi
    if [ -e '.deploy.pull' ]; then
        rm ".deploy.pull"
        git pull --autostash
        npm install
    fi
    [ -z "$RESTART" ] && break
done

