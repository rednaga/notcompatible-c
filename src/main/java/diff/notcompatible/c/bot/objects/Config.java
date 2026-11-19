package diff.notcompatible.c.bot.objects;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import diff.notcompatible.c.bot.crypto.RC4;

// "Config packet"
public class Config {

    private final static Logger LOGGER = Logger.getLogger("session");

    public Packet packet;
    public File directory;

    public Config(File sessionDirectory) {
        directory = sessionDirectory;
    }

    // Saves a "data.bin"
    public void save(File path) {
        try {
            // "generate key"
            byte[] key = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, };

            byte[] cryptedConfig = new RC4(key).crypt(packet.pack());
            DataOutputStream file = new DataOutputStream(new FileOutputStream(directory.getPath() + "/data.bin"));
            file.write(cryptedConfig);
            file.flush();
            file.close();
        } catch (Exception exception) {
            LOGGER.throwing(exception.getClass().getName(), "save()", exception);
            exception.printStackTrace();
        }
    }

    /**
     * The bot keeps its config under a "CONFIG" root packet: SET (the signed config: Sign + DATA) is a
     * child of it, next to the UUID / GROUP / PORT / INDEXGROUP / LDGROUP / FB values the bot adds
     * itself. resources/default.config is just the SET packet, so it gets wrapped. data.bin files
     * written by earlier versions of this class had SET as the root with those values inside it; they
     * are migrated.
     */
    static Packet toConfigRoot(Packet loaded) {
        if ((loaded != null) && loaded.tag.equals("CONFIG")) {
            return loaded;
        }

        Packet root = new Packet();
        root.tag = "CONFIG";
        if (loaded != null) {
            root.add(loaded);
            for (String tag : new String[] { "UUID", "GROUP", "PORT", "INDEXGROUP", "LDGROUP", "FB" }) {
                Packet moved = loaded.getByName(tag);
                if (moved != null) {
                    loaded.delete(tag);
                    root.add(moved);
                }
            }
        }
        return root;
    }

    // Loads a "config packet"
    // This normally loads "data.bin" in current location - otherwise load the "data" from "res/raw"
    public void load() {
        boolean isChanged = false;
        try {
            File config = new File(directory.getPath() + "/data.bin");
            if (!config.exists()) {
                config = new File("resources/default.config");
            }

            InputStream fi = new FileInputStream(config);

            byte buffer[] = new byte[fi.available()];

            DataInputStream dis = new DataInputStream(fi);
            dis.read(buffer);
            dis.close();

            // "generate key"
            byte[] key = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, };

            RC4 rc4 = new RC4(key);
            byte[] buffer2 = rc4.crypt(buffer);

            MyBuffer mb = new MyBuffer();
            mb.put(buffer2);
            packet = toConfigRoot(Packet.unpack(mb));

            // No UUID, generate one
            if (packet.getByName("UUID") == null) {
                byte[] uid = new byte[16];
                for (int i = 0; i < uid.length; i++) {
                    // config.Load: (byte) (int) (Math.random() * 256.0)
                    uid[i] = (byte) ((int) (Math.random() * 256.0));
                }

                Packet uuid = packet.add();
                uuid.tag = "UUID";
                uuid.buffer.put(uid);
                isChanged = true;
            }

            // No group - make one
            if (packet.getByName("GROUP") == null) {
                // Odd but the local var is named port for group...
                Packet port = packet.add();
                port.tag = "GROUP";
                port.buffer.putWord(0);
                isChanged = true;
            }

            // No port - make one
            if (packet.getByName("PORT") == null) {
                // config.Load: (int) (2048.0 + Math.random() * 35000.0). (The smali shows these as raw
                // IEEE-754 bit patterns, 0x40a0000000000000 and 0x40e1170000000000; an earlier version of
                // this class parsed those bit patterns as decimal numbers, so every UUID byte was 0xFF
                // and the port was always 65535.)
                int portn = (int) (2048.0 + Math.random() * 35000.0);
                Packet port = packet.add();
                port.tag = "PORT";
                port.buffer.putWord(portn);
                isChanged = true;
            }

            dis.close();
            fi.close();

            if (isChanged) {
                save(new File(directory.getPath()));
            }
        } catch (IOException exception) {
            LOGGER.throwing(exception.getClass().getName(), "load()", exception);
            exception.printStackTrace();
        }
    }

}
