package diff.notcompatible.c.bot.net.udp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.crypto.RSA;
import diff.notcompatible.c.bot.net.udp.objects.UDPHeader;
import diff.notcompatible.c.bot.net.udp.objects.UDPRemPointList;
import diff.notcompatible.c.bot.objects.HubListItem;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

public class UDPPoint {

	private final static Logger LOGGER = Logger.getLogger("session");
	
	public byte[] rc4key;
	public InetSocketAddress endPoint;
	public boolean isEncrypt;
	public boolean isPunch;
	public long lastChangeTime;
	public UDPRemPointList remlist;
	public byte keepByte;
	public HubListItem hr;
	public UDPMixer owner;
	public int seq;
	public UDPQuery query;
	public long longCheckTime;
	public int status;
	public boolean sendSUIPAfter;

	public UDPPoint(UDPMixer newOwner) {
		owner = newOwner;
		remlist = new UDPRemPointList();
	}

	public void onReadySeq(byte[] data) {
        MyBuffer buffer = new MyBuffer();
        buffer.put(data);
        Packet packet = Packet.unpack(buffer);
        if (packet != null) {
            if (packet.tag.equals("SUIP")) {
                recvSUIP(packet);
            }else if (packet.tag.equals("PING")) {
                sendPONG();
            }else if (packet.tag.equals("PONG")) {
                recvPONG(packet);
            }else if (packet.tag.equals("PINGME")) {
                recvPINGME(packet);
            }else if (packet.tag.equals("PINGTO")) {
                recvPINGTO(packet);
            }else if (packet.tag.equals("SET")) {
                recvSET(packet);
            }else if (packet.tag.equals("GETSET")) {
                sendSET();
            }else if (packet.tag.equals("LID")) {
                recvLID(packet);
            }else if (packet.tag.equals("GETHUB")) {
                sendHUBList();
            }else if (packet.tag.equals("UDPHUBLIST")) {
                recvHUBLIST(packet);
            }else if (packet.tag.equals("GETPOINT")) {
                sendList();
            }else if (packet.tag.equals("PUSH")) {
                recvPUSH(packet);
            }else if (packet.tag.equals("LIST")) {
                recvLIST(packet);
            }else if (packet.tag.equals("PUSHTO")) {
                recvPUSHTO(packet);
            }else {
            	LOGGER.warning(" [!] Hit an unknown UDP command!");
            }
        }
	}
	
    public void onRecv(byte[] data) {
        byte[] payloadContents = new byte[data.length - 1];
        System.arraycopy(data, 1, payloadContents, 0, payloadContents.length);
        
        // Check command byte
        switch (data[0]) {
            case (byte) 0:
                recvPublic(payloadContents);
                lastChangeTime = System.currentTimeMillis();
                return;
            case (byte) 1:
                recvRC4key(payloadContents);
                lastChangeTime = System.currentTimeMillis();
                return;
            case (byte) 2:
                if (isEncrypt) {
                    query.postData(payloadContents);
                    lastChangeTime = System.currentTimeMillis();
                    return;
                } else {
                    sendPublic();
                    return;
                }
            case (byte) 3:
                isPunch = false;
                sendPublic();
                return;
            case (byte) 4:
                isPunch = false;
                return;
        }
        owner.list.delete(this);
    }

	public void check() {
		if (isPunch) {
            sendKEEP();
        } else {
            query.check();
            if (lastChangeTime + 30000 > longCheckTime && isEncrypt) {
                sendPING();
            }
           
			if (longCheckTime + 40000 < System.currentTimeMillis()) {
                longCheckTime = System.currentTimeMillis();
                if (remlist.candidateCount() == 0 && isEncrypt) {
                    sendGETPOINT();
                }
            }
        }
	}

	public void doDelete(boolean good) {
        if (hr != null) {
            if (good) {
                hr.status = 1;
            } else {
                hr.status = -1;
            }
            hr.used = false;
        }
        owner.list.delete(this);
	}
	
	public void recvPublic(byte[] data){
		LOGGER.info(" [+] Receiving a public key over UDP");
        RSA tmpRSA = new RSA();
        if (tmpRSA.loadPublic(data)) {
            byte[] tmp = new byte[101];
            for(int i = 0; i < tmp.length; i++)
                tmp[i] = (byte) ((int) Math.round(Math.random() * 256.0d));

            tmp[0] = (byte) 0x7;
            System.arraycopy(tmp, 1, rc4key, 0, 100);
            
            byte[] tmp2 = tmpRSA.encrypt(tmp);
            if (tmp2 == null) {
                owner.list.delete(this);
            } else {
            	MyBuffer buffer = new MyBuffer();
            	
                buffer.put((byte) 1);
                buffer.put(tmp2);
                send(buffer.array());
                
                status = 3;
                isEncrypt = true;
                if (owner.owner.udpList.count() < 1000) {
                    sendGETHUB();
                }
                sendGETPOINT();
            }
        } else {
            doDelete(false);
        }
	}
	
	public void recvRC4key(byte[] data){
		LOGGER.info(" [+] Receiving a rc4 key over UDP");
        rc4key = owner.owner.RSALocal.decrypt(data);
        byte[] tmp2 = new byte[100];
        System.arraycopy(rc4key, 1, tmp2, 0, tmp2.length);
        rc4key = tmp2;
        status = 3;
        isEncrypt = true;
        if (!owner.owner.isIPDetected) {
            sendPINGME();
        }
        if (sendSUIPAfter) {
            sendSUIP();
        }
        sendLID();
        if (owner.owner.udpList.count() < 1000) {
            sendGETHUB();
        }
	}
	
	public void recvSET(Packet packet){
		LOGGER.info(" [+] Receiving a SETing packet over UDP");
        Packet dataPacket = packet.getByName("DATA");
        if (dataPacket != null) {
        	Packet signPacket = packet.getByName("Sign");
            if (signPacket != null) {
            	Packet lidPacket = dataPacket.getByName("LID");
                if (lidPacket != null && owner.owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64() < lidPacket.asInt64()
                		&& owner.owner.RSAGlobal.check(dataPacket.getDigest(), signPacket.array())) {
                	owner.owner.config.packet.delete("SET");
                    owner.owner.config.packet.add(packet);
                    owner.owner.config.save(owner.owner.sessionDirectory);
                    owner.owner.connectionManager.load();
                    owner.owner.sendSET();
                }
            }
        }
	}
	
	public void recvHUBLIST(Packet packet){
        owner.owner.udpList.loadFromPacket(packet);
        owner.owner.saveUDPHubList();
	}
	
	public void recvPONG(Packet packet){
		LOGGER.info(" [+] Received a PONG over UDP");
		// Nothing
	}
	
	public void recvPINGME(Packet packet){
		LOGGER.info(" [+] Received a PINGME over UDP");
        Packet pingToPacket = new Packet();
        pingToPacket.tag = "PINGTO";
        pingToPacket.buffer.putIP(endPoint.getAddress().getHostAddress());
        pingToPacket.buffer.putPort(endPoint.getPort());
    	for(int i = 0; i < owner.list.count(); i++) {
            UDPPoint up = owner.list.getByIndex(i);
            if (up != this && up.isEncrypt) {
                up.send(pingToPacket);
                return;
            }
        }
	}
	
	public void recvPINGTO(Packet packet){
		LOGGER.info(" [+] Received a PINGTO over UDP");
        if (packet.buffer.size == 6) {
            String ip = packet.asIP();
            packet.buffer.shift(4);
            int port = packet.asPort();
            if (owner.list.getByInetSocketAddress(new InetSocketAddress(ip, port)) == null) {
                UDPPoint up = owner.createLink(ip, port);
                if (up != null) {
                    up.sendSUIPAfter = true;
                    up.sendPublic();
                }
            }
        }
	}
	
	public void recvSUIP(Packet packet){
		LOGGER.info(" [+] Received a SUIP over UDP");
		long currentTime = System.currentTimeMillis();
		String ip = packet.asIP();
		packet.buffer.shift(4);
		int port = packet.asPort();
		
		owner.owner.IPDetected(ip);
		HubListItem item = owner.owner.udpList.getByIpAndPort(ip, port);
		if(item == null) {
			item = owner.owner.udpList.add();
			item.ip = ip;
			item.port = port;
		}
		
		item.connectCount = 0;
		item.lastConnect = currentTime;
		item.lastTested = currentTime;
		item.status = 1;
		item.used = true;
	}
	
	public void recvLID(Packet packet){
		LOGGER.info(" [+] Received a LID over UDP");
        if (owner.owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64() < packet.asInt64()) {
            sendGetSET();
        }else if (owner.owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64() > packet.asInt64()) {
            sendSET();
        }
	}
	
	public void recvLIST(Packet packet){
		LOGGER.info(" [+] Received a LIST over UDP");
		for(int i = 0; i < packet.getCount(); i ++) {
            Packet item = packet.getByIndex(i);
            if (item.tag.equals("Item")) {
                String ip = item.asIP();
                item.buffer.shift(4);
                remlist.add(new InetSocketAddress(ip, item.asPort()));
            }
        }
	}
	
	public void recvPUSHTO(Packet packet){
		LOGGER.info(" [+] Received a PUSHTO over UDP");
        if (packet.buffer.size == 6) {
            String ip = packet.asIP();
            packet.buffer.shift(4);
            int port = packet.asPort();
            if (owner.list.getByInetSocketAddress(new InetSocketAddress(ip, port)) == null) {
                UDPPoint up = owner.createLink(ip, port);
                if (up != null) {
                    keepByte = (byte) 4;
                    up.isPunch = true;
                    up.sendKEEP();
                }
            }
        }
	}
	
	public void recvPUSH(Packet packet){
		LOGGER.info(" [+] Received a PUSH over UDP");
        if (packet.buffer.size == 6) {
            String ip = packet.asIP();
            packet.buffer.shift(4);
            UDPPoint up = owner.list.getByInetSocketAddress(new InetSocketAddress(ip, packet.asPort()));
            if (up != null && up.isEncrypt) {
                up.sendPUSHTO(endPoint.getAddress().getHostAddress(), endPoint.getPort());
            }
        }
	}

	public void sendGETHUB() {
		LOGGER.info(" [+] Sending a GETHUB over UDP");
		Packet packet = new Packet();
		packet.tag = "GETHUB";
		send(packet);
	}
	
	public void sendGETPOINT() {
		LOGGER.info(" [+] Sending a GETPOINT over UDP");
		Packet packet = new Packet();
		packet.tag = "GETPOINT";
		send(packet);
	}
	
	public void sendGetSET() {
		LOGGER.info(" [+] Sending a GetSET over UDP");
		Packet packet = new Packet();
		packet.tag = "GETSET";
		send(packet);
	}

	public void sendSUIP() {
		LOGGER.info(" [+] Sending a SUIP over UDP");
        MyBuffer buffer = new MyBuffer();
        Packet packet = new Packet();
        
        buffer.putIP(endPoint.getAddress().getHostAddress());
        buffer.putPort(endPoint.getPort());
        packet.tag = "SUIP";
        packet.buffer.put(buffer.array());
        
        send(packet);
	}
	
	public void sendPUSH(String hostAddress, long port) {
		LOGGER.info(" [+] Sending a PUSH over UDP");
		MyBuffer buffer = new MyBuffer();
		buffer.putIP(hostAddress);
		buffer.putPort(port);
		
		Packet packet = new Packet();
		packet.tag = "PUSH";
		packet.buffer =  buffer;
		
		send(packet);
	}
	
	public void sendPUSHTO(String hostAddress, long port) {
		LOGGER.info(" [+] Sending a PUSHTO over UDP");
		MyBuffer buffer = new MyBuffer();
		buffer.putIP(hostAddress);
		buffer.putPort(port);
		
		Packet packet = new Packet();
		packet.tag = "PUSHTO";
		packet.buffer =  buffer;
		
		send(packet);
	}

	public void sendKEEP() {
		LOGGER.info(" [+] Sending a KEEP over UDP");
        byte[] data = new byte[1];
        data[0] = keepByte;
        send(data);
	}
	
	public void sendPONG() {
		LOGGER.info(" [+] Sending a PONG over UDP");
		Packet packet = new Packet();
		packet.tag = "PONG";
		send(packet);
	}
	
	public void sendPING() {
		LOGGER.info(" [+] Sending a PING over UDP");
		Packet packet = new Packet();
		packet.tag = "PING";
		send(packet);
	}
	
	public void sendPINGME() {
		LOGGER.info(" [+] Sending a PINGME over UDP");
		Packet packet = new Packet();
		packet.tag = "PINGME";
		send(packet);
	}
	
	public void sendHUBList() {
		LOGGER.info(" [+] Sending a HUBList over UDP");
		send(owner.owner.udpList.getHubListFordSend());
	}
	
	public void sendList() {
		LOGGER.info(" [+] Sending a List over UDP");
        Packet listPacket = new Packet();
        listPacket.tag = "LIST";
        
        for(int i = 0; i < owner.count(); i++) {
            UDPPoint udpPoint = owner.list.getByIndex(i);
            if (udpPoint.isEncrypt) {
                Packet pointPacket = listPacket.add();
                pointPacket.tag = "Item";
                pointPacket.buffer.putIP(udpPoint.endPoint.getAddress().getHostAddress());
                pointPacket.buffer.putPort(udpPoint.endPoint.getPort());
            }
        }
        
        send(listPacket);
	}
	
	public void sendSET() {
		LOGGER.info(" [+] Sending a SET over UDP");
		send(owner.owner.config.packet.getByName("SET"));
	}

	public void sendLID() {
		LOGGER.info(" [+] Sending a LID over UDP");
        Packet packet = new Packet();
        packet.tag = "LID";
        packet.buffer.putInt64(owner.owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64());
        send(packet);
	}

	public void sendPublic() {
		LOGGER.info(" [+] Sending a Public key over UDP");
        byte[] modulus = owner.owner.RSALocal.rsaPublicKey.getModulus().toByteArray();
        if (modulus[0] == 0x00) {
            byte[] tmp = new byte[(modulus.length - 1)];
            System.arraycopy(modulus, 1, tmp, 0, tmp.length);
            modulus = tmp;
        }
        MyBuffer buffer = new MyBuffer();
        buffer.put((byte) 0);
        buffer.put(modulus);
        
        send(buffer.array());
        status = 2;
	}
	
    public void send(Packet packet) {
        UDPHeader header = new UDPHeader();
        MyBuffer buffer = new MyBuffer();
        MyBuffer ot = new MyBuffer();
        
        buffer.put(packet.pack());
        seq++;
        header.sequence = seq;
        header.part = (buffer.size + 499) / 500;
        for(int i = 0; i < header.part; i++) {
            byte[] r = buffer.read(500);
            if (r.length > 0) {
                header.count = i;
                ot.clear();
                ot.put(header.pack());
                ot.put(r);
                sendEncrypt(ot.array());
            }
        }
    }
	
    public void send(byte[] data) {
        ByteBuffer tmp = ByteBuffer.allocate(data.length);
        tmp.put(data);
        tmp.position(0);
        try {
            owner.channel.send(tmp, endPoint);
        } catch (IOException exception) {
        	exception.printStackTrace();
        }
    }

    public void sendEncrypt(byte[] data) {
        RC4 rc4 = new RC4(rc4key);
        ByteBuffer tmp = ByteBuffer.allocate(data.length + 1);
        
        tmp.put((byte) 2);
        tmp.put(rc4.crypt(data));
        tmp.position(0);
        try {
            owner.channel.send(tmp, endPoint);
        } catch (IOException exception) {
        	exception.printStackTrace();
        }
    }
}
