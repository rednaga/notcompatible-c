notcompatible-c
===============

NotCompatible-C Bot reversed, for using in watching the bot, decoding and probing

Code needs to be cleaned up a bit more, though it is essentially fully functional, though
I have yet to find nodes which cleanly connect via UDP/P2P due to NAT issues.

Code has some fixes in it as there are some nuances between regular Java and Android. Timing was
a little bit of a problem as the server takes a while for the Link to establish so I added some
short timeouts which seem to fix the issue.
