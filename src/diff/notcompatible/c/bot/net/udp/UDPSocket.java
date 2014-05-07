package diff.notcompatible.c.bot.net.udp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;

import diff.notcompatible.c.bot.net.CustomSocket;

public class UDPSocket extends CustomSocket {
    public DatagramChannel channel;
    public Selector selector;

    public UDPSocket(Selector newSelector) {
        selector = newSelector;
    }

    public void bind(int port) throws IOException {
        channel = DatagramChannel.open();
        channel.socket().setReuseAddress(true);
        channel.socket().bind(new InetSocketAddress(port));
        channel.configureBlocking(false);
        channel.register(selector, 1).attach(this);
    }

    @Override
    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);
    }
}
