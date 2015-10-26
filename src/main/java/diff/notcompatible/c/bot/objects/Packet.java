package diff.notcompatible.c.bot.objects;

import java.security.MessageDigest;
import java.util.logging.Logger;

public class Packet {

    private final static Logger LOGGER = Logger.getLogger("session");

    public MyBuffer buffer;
    public List list;
    public String tag;

    public Packet() {
        list = new List();
        tag = "";
        buffer = new MyBuffer();
    }

    public Packet add() {
        Packet packet = new Packet();

        list.add(packet);

        return packet;
    }

    public void delete(String tag) {
        list.delete(getByName(tag));
    }

    public void add(Packet packet) {
        list.add(packet);
    }

    public byte[] array() {
        return buffer.array();
    }

    public byte asByte() {
        return buffer.asByte();
    }

    public int asDWord() {
        return buffer.asDWord();
    }

    public String asIP() {
        byte[] ip = buffer.array();
        return "" + (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    public long asInt64() {
        return buffer.asInt64();
    }

    public int asPort() {
        byte[] port = buffer.array();
        return ((port[0] & 0xFF) << 8) | (port[1] & 0xFF);
    }

    public String asString() {
        return new String(buffer.array());
    }

    public int asWord() {
        return buffer.asWord();
    }

    public void clear() {
        list.clear();
        buffer.clear();
    }

    public Packet getByIndex(int index) {
        if (index >= list.count) {
            return null;
        } else {
            return (Packet) list.getObject(index);
        }
    }

    public Packet getByName(String tagName) {
        Packet packet = null;

        if (tag.equals(tagName)) {
            packet = this;
        }

        for (int i = 0; i < list.count; i++) {
            // It technically should use contentEquals or something
            if (((Packet) list.getObject(i)).tag.equals(tagName)) {
                packet = (Packet) list.getObject(i);
                break;
            }
        }

        return packet;
    }

    public byte[] getDigest() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");

            md.reset();
            md.update(pack());

            return md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public int getCount() {
        return list.count;
    }

    public int getSize() {
        int size = tag.length() + 5 + buffer.size;

        for (int i = 0; i < list.count; i++) {
            size += ((Packet) list.getObject(i)).getSize();
        }

        return size;
    }

    public byte[] pack() {
        MyBuffer out = new MyBuffer();

        // Packet tag + data size
        out.putDword(this.getSize());

        // Tag size and data
        byte size = (byte) tag.length();
        if (list.count > 0) {
            size = (byte) (size | 128);
        }
        out.put(size);
        out.put(tag.getBytes());

        // packet data
        for (int i = 0; i < list.count; i++) {
            out.put(((Packet) list.getObject(i)).pack());
        }

        out.put(buffer.array());

        return out.array();
    }

    public static Packet unpack(MyBuffer data) {
        Packet packet = null;

        // Nothing to parse, ignore it (we always hit this at the end of the buffer)
        if (data.size == 0) {
            return packet;
        }

        // No packet is size + 1 byte!
        if (data.size > 5) {
            int size = data.asDWord();
            // Something is wrong if the size it out of bounds
            if (data.size >= size) {
                boolean notSinglePacket;

                // Copy out the data for the packet
                byte[] rawPacketData = new byte[size];
                data.buffer.position(0);
                data.buffer.get(rawPacketData, 0, size);
                data.shift(size);

                // Dump data into buffer, shift over the size and parse as packet
                packet = new Packet();
                MyBuffer buffer = new MyBuffer();
                buffer.put(rawPacketData);
                buffer.shift(4);
                size -= 4;

                // Parse the tag size byte, shift over it and parse the tag string
                int tagsize = buffer.asByte() & 0x7F;
                notSinglePacket = ((byte) ((buffer.asByte() & 0x80) >> 7)) != 0;
                buffer.shift(1);
                byte[] tag = new byte[tagsize];
                buffer.buffer.position(0);
                buffer.buffer.get(tag, 0, tagsize);
                packet.tag = new String(tag);
                buffer.shift(tagsize);

                size = size - 1 - tagsize;
                // More packets to parse?
                if (notSinglePacket) {
                    while (buffer.size != 0) {
                        Packet recursivePacket = unpack(buffer);
                        if (recursivePacket != null) {
                            packet.list.add(recursivePacket);
                        }
                    }
                } else {
                    // Add the buffer (if it's there)
                    byte[] packetBuffer = new byte[size];
                    buffer.buffer.position(0);
                    buffer.buffer.get(packetBuffer, 0, size);
                    packet.buffer.put(packetBuffer);
                }
            }
        } else {
            LOGGER.warning(" [!] Packet seemed bad, throwing away!");
        }

        return packet;
    }

    @Override
    public String toString() {
        if ((tag == null) || tag.equals("")) {
            return "Nothing to stringify!";
        } else if (tag.equals("PING")) {
            return "PING";
        } else if (tag.equals("DATA")) {
            return "DATA";
        } else if (tag.equals("SERV")) {
            return "SERV";
        } else if (tag.equals("DOM")) {
            return "DOM : " + this.asString();
        } else if (tag.equals("NAME")) {
            return "NAME : " + this.asString();
        } else if (tag.equals("PORT")) {
            return "PORT : " + this.asPort();
        } else if (tag.equals("IP")) {
            return "IP : " + this.asIP();
        } else if (tag.equals("ID")) {
            return "ID : " + this.asByte();
        } else if (tag.equals("LID")) {
            return "LID : " + this.asInt64();
        } else if (tag.equals("Sign")) {
            return "Sign";
        } else if (tag.equals("SET")) {
            return "SET";
        } else if (tag.equals("GROUP")) {
            return "GROUP";
        } else if (tag.equals("SETGROUP")) {
            return "SETGROUP : " + this.asByte();
        } else if (tag.equals("HUBLIST")) {
            return "HUBLIST";
        } else if (tag.equals("Item")) {
            return "Item";
        } else if (tag.equals("Port")) {
            return "Port : " + this.asPort();
        } else if (tag.equals("CH")) {
            return "CH : " + this.asByte();
        } else if (tag.equals("DT")) {
            return "DT : " + this.asString();
        } else if (tag.equals("UDPHUBLIST")) {
            return "UDPHUBLIST";
        } else if (tag.equals("CONN")) {
            String host = "unknown";
            if (getByName("DOM").toString() == null) {
                host = getByName("IP").toString();
            } else {
                host = getByName("DOM").toString();
            }
            return "CONN : " + getByName("CH").toString() + " " + host + " / " + getByName("PORT").toString();
        } else if (tag.equals("SHUT")) {
            return "SHUT : " + getByName("CH").toString() + " " + getByName("DT").toString();
        } else {
            return "Not done yet! [ " + tag + " ]";
        }
    }

}
