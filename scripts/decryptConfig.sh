#!/bin/sh

if [[ -z "$NCJAR" ]]; then
    echo 'Must set $NCJAR environment variable first!'
else
    java -cp $NCJAR diff.notcompatible.c.bot.decrypt $1
fi