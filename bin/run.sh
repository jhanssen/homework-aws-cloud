#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
[ -e /etc/homework/homework.config ] && . /etc/homework/homework.config
cd $DIR/../src
while true; do
    RESTART=1
    ./server.js 2>&1 | tee log
    if [ ! "${PIPESTATUS[0]}" -eq 0 ]; then
        /bin/mv log crash.log.`date +%s`
        RESTART=
    fi
    if [ -e '.deploy.pull' ]; then
        rm ".deploy.pull"
        git pull --autostash
        npm install
    fi
    [ -z "$RESTART" ] && break
done

