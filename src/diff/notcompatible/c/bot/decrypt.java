package diff.notcompatible.c.bot;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

public class decrypt {

    public static void main(String args[]) {
        try {
            // TODO : Extract this out
            // If the local one is not found - we should read this default and cause a save to occur
            InputStream fi = new FileInputStream(new File(args[0]));

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
            Packet pac = Packet.unpack(mb);

            if (pac.tag.equals("SET")) {
                System.out.println("[*] SET(ting) packet found");
                if (pac.getByName("Sign") != null) {
                    System.out.println(" [+] Sign(ature) packet found");
                    pac.getByName("Sign").buffer.array(); // 128
                }
                Packet data = pac.getByName("DATA");
                if (data != null) {
                    System.out.println(" [*] DATA packet found!");
                    Packet group = data.getByName("GROUP");
                    if (group != null) {
                        // -> ID size 2
                        if (group.getByName("ID") != null) {
                            System.out.println("  [+] ID packet found : [ " + group.getByName("ID").asWord() + " ]");
                        }
                        // GROUP
                        // -> SERV
                        // --> IP
                        // --> PORT
                        Packet server = group.getByName("SERV");
                        if (server != null) {
                            System.out.println("  [*] SERV(er) packet found");
                            if ((server.getByName("IP") != null) && (server.getByName("PORT") != null)) {
                                System.out.println("   [+] IP Address : [ " + server.getByName("IP").asIP() + " ]");
                                System.out.println("   [+] Port : [ " + server.getByName("PORT").asPort() + " ]");
                            }
                        }
                    }
                    // LID size 8
                    if (data.getByName("LID") != null) {
                        System.out.println(" [+] LID packet found : [ " + data.getByName("LID").asInt64() + " ]");
                    }
                }
            }

            // No UUID, generate one
            if (pac.getByName("UUID") == null) {
                byte[] uid = new byte[16];
                for (int i = 0; i < uid.length; i++) {
                    uid[i] = (byte) ((int) (Math.random() * Double.parseDouble("4643211215818981376")));
                }

                Packet uuid = pac.add();
                uuid.tag = "UUID";
                uuid.buffer.put(uid);
            }

            // No group - make one
            if (pac.getByName("GROUP") == null) {
                // Odd but the local var is named port for group...
                Packet port = pac.add();
                port.tag = "GROUP";
                port.buffer.putWord(0);
            }

            // No port - make one
            if (pac.getByName("PORT") == null) {
                int portn = (int) (Double.parseDouble("4656722014701092864") * Math.random() * Double
                                .parseDouble("4675043176954724352"));
                Packet port = pac.add();
                port.tag = "PORT";
                port.buffer.putWord(portn);
            }

            dis.close();
            fi.close();

        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }

}
