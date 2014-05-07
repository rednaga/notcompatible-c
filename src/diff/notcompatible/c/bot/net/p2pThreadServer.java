package diff.notcompatible.c.bot.net;

import java.util.logging.Logger;

import diff.notcompatible.c.bot.net.tcp.objects.P2PConnectionList;

public class p2pThreadServer extends ThreadServer {

    private final static Logger LOGGER = Logger.getLogger("session");

    public p2pThreadServer(Object ownerObject) {
        super(ownerObject);
        nio = null;
        connectionType = 0;
        lastCheckHub = 0;
        lastCheckP2P = 0;
        lastCheckUDP = 0;
        isOpenPort = false;
        isOpenPortTested = 0;
        isIPDetected = false; // Misspelled to isIPDetedted
        ip = "";
        port = 0;
        owner = ownerObject;

        try {
            nio = new NIOServer();
            socks = null;
            p2plist = new P2PConnectionList();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "p2pThreadServer()", exception);
            exception.printStackTrace();
        }
    }

    @Override
    public void createUDPMixer() {
        // We don't want to look at UDP in the bot for testing
    }

    @Override
    public void checkUDP() {
        // We don't want to look at UDP in the bot for testing
    }
}
