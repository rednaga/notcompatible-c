#!/bin/sh

if [[ -z "$NCJAR" ]]; then
    echo 'Must set $NCJAR environment variable first!'
else
    java -cp $NCJAR diff.notcompatible.c.bot.readHubs $1
fi