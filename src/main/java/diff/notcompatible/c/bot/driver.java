package diff.notcompatible.c.bot;

import java.io.File;
import java.security.Security;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import diff.notcompatible.c.bot.net.ThreadServer;

public class driver {

    private final static Logger LOGGER = Logger.getLogger("session");

    static ThreadServer threadServer;

    public static void main(String[] args) {
        File serverPublicKey = null;
        File sessionDirectory = null;
        File clientPublicKey = null;
        File clientPrivateKey = null;
        long currentTime = System.currentTimeMillis();

        try {
            // Server public RSA key - will use resources/default.bin if nothing passed
            if ((args.length > 0) && (args[0] != null)) {
                serverPublicKey = new File(args[0]);
            }

            // Session directory, where things will be dumped/saved/loaded from if there is stuff
            // Specifically the config will be saved here, crypto keys, proxylinks and tcp/udp peers
            // defaults to out/%current_system_time%/
            if ((args.length > 2) && (args[1] != null)) {
                sessionDirectory = new File(args[1]);
            } else {
                sessionDirectory = new File("out/" + currentTime + "/");
            }

            if (!sessionDirectory.exists()) {
                if (sessionDirectory.mkdirs()) {
                    LOGGER.info("Created session directory : [ " + sessionDirectory.getPath() + " ] ");
                } else {
                    LOGGER.warning("Error creating session directory!");
                }
            }

            // Client public and private RSA keys
            if ((args.length >= 3) && (args[2] != null) && (args[3] != null)) {
                clientPublicKey = new File(args[2]);
                clientPrivateKey = new File(args[3]);
            }

            // Required for crypto magic
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Handler handler = new FileHandler(sessionDirectory + "/session.log");
            handler.setFormatter(new SimpleFormatter());
            Logger.getLogger("session").addHandler(handler);

            LOGGER.info(" [*] New session started at : [ " + currentTime + " ]");

            Object owner = new Object();
            threadServer = new ThreadServer(owner);
            threadServer.init(sessionDirectory, serverPublicKey, clientPublicKey, clientPrivateKey);
            threadServer.run();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "main", exception);
            exception.printStackTrace();
        }
    }
}
