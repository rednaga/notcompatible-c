notcompatible-c
===============

NotCompatible-C Bot reversed, for using in watching the bot, decoding and probing

Code needs to be cleaned up a bit more, though it is essentially fully functional, though
I have yet to find nodes which cleanly connect via UDP/P2P due to NAT issues.

Code has some fixes in it as there are some nuances between regular Java and Android. Timing was
a little bit of a problem as the server takes a while for the Link to establish so I added some
short timeouts which seem to fix the issue.

Building
--------
There is an ant file now for conveince and avoid using Eclipse. Simply
type "ant jar" to compile a jar - it will be dumped into the "dist/"
directory with a timestamp added;

>bebop:not-compatible tstrazzere$ ant jar
>Buildfile: /Users/tstrazzere/Documents/workspace/not-compatible/build.xml
>
>init:
>
>compile:
>    [mkdir] Created dir: /Users/tstrazzere/Documents/workspace/not-compatible/bin/classes
> [my.javac] Compiling 45 source files to /Users/tstrazzere/Documents/workspace/not-compatible/bin/classes
>
>jar:
>    [mkdir] Created dir: /Users/tstrazzere/Documents/workspace/not-compatible/dist
>      [jar] Building jar: /Users/tstrazzere/Documents/workspace/not-compatible/dist/nc-bot-20140505.jar
>
>BUILD SUCCESSFUL
>Total time: 1 second
