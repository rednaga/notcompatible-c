package diff.notcompatible.c.bot.objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import diff.notcompatible.c.bot.crypto.RSA;
import diff.notcompatible.c.bot.objects.sort.HubListSortConnected;

/** Behaviour taken from the reversed samples (see docs/sample-weaknesses.md) for the shared data structures. */
class SampleStructuresTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void configIsRootedAtConfigWithSetChild(@TempDir File dir) {
        Config config = new Config(dir);
        config.load();

        assertEquals("CONFIG", config.packet.tag);
        Packet set = config.packet.getByName("SET");
        assertNotNull(set, "SET (the signed config) is a child of CONFIG");
        assertNotNull(set.getByName("Sign"));
        assertEquals(1L, set.getByName("DATA").getByName("LID").asInt64());

        // The bot-generated values sit next to SET, not inside it
        byte[] uuid = config.packet.getByName("UUID").array();
        assertEquals(16, uuid.length);
        int port = config.packet.getByName("PORT").asWord();
        assertTrue(port >= 2048 && port < 2048 + 35000, "port " + port);
        assertNull(set.getByName("UUID"));

        // Regression: UUID bytes used to all be 0xFF and the port always 65535
        boolean allFf = true;
        for (byte b : uuid) {
            allFf &= (b == (byte) 0xFF);
        }
        assertFalse(allFf, "uuid must be random");

        // Saved as data.bin and read back unchanged
        Config again = new Config(dir);
        again.load();
        assertEquals("CONFIG", again.packet.tag);
        assertArrayEquals(uuid, again.packet.getByName("UUID").array());
        assertEquals(port, again.packet.getByName("PORT").asWord());
    }

    @Test
    void olderSetRootedConfigIsMigrated() {
        Packet legacy = new Packet();
        legacy.tag = "SET";
        legacy.add().tag = "DATA";
        Packet uuid = legacy.add();
        uuid.tag = "UUID";
        uuid.buffer.put(new byte[] { 1, 2, 3 });
        Packet group = legacy.add();
        group.tag = "GROUP";
        group.buffer.putWord(0);

        Packet root = Config.toConfigRoot(legacy);
        assertEquals("CONFIG", root.tag);
        assertNotNull(root.getByName("SET").getByName("DATA"));
        assertNull(root.getByName("SET").getByName("UUID"));
        assertArrayEquals(new byte[] { 1, 2, 3 }, root.getByName("UUID").array());
        assertNotNull(root.getByName("GROUP"));
    }

    @Test
    void getByNameOnlyLooksAtChildren() {
        Packet parent = new Packet();
        parent.tag = "SET";
        assertNull(parent.getByName("SET"));
        parent.add().tag = "DATA";
        assertNotNull(parent.getByName("DATA"));
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void hubSortPutsMostRecentlyConnectedFirstAndTerminates() {
        // the comparator used to compare object2 with itself, which made every sort a no-op
        for (int size : new int[] { 2, 3, 7, 50 }) {
            HubList hubs = new HubList();
            for (int i = 0; i < size; i++) {
                HubListItem item = hubs.add();
                item.ip = "10.0.0." + i;
                item.lastConnect = (i * 7919L) % 101; // scrambled, with some repeats
            }
            hubs.list.sort(new HubListSortConnected());
            for (int i = 1; i < size; i++) {
                // list.prSort() in the bot is a descending quicksort: most recent LastConnect first
                assertTrue(hubs.getByIndex(i - 1).lastConnect >= hubs.getByIndex(i).lastConnect,
                                "size " + size + " not sorted at " + i);
            }
        }
    }

    @Test
    void listEdgeCases() {
        List list = new List();
        assertNull(list.getObject(0));
        list.add("a");
        assertNull(list.getObject(5), "out of range is null, not an NPE");
        assertNull(list.getItem(5));
    }

    @Test
    void hubListSentToPeersIsAlwaysEmpty() {
        HubList hubs = new HubList();
        hubs.tag = "HUBLIST";
        HubListItem item = hubs.add();
        item.ip = "10.1.2.3";
        item.port = 443;
        item.lastConnect = System.currentTimeMillis();
        item.used = true;

        Packet packet = hubs.getHubListFordSend();
        assertEquals("HUBLIST", packet.tag);
        assertEquals(0, packet.getCount(), "the bot's GetHubListForSend loop never runs");
    }

    @Test
    void rsaCheckComparesTheDigestSizedTail() {
        RSA rsa = new RSA();
        rsa.genKey();
        byte[] digest = new byte[20];
        for (int i = 0; i < digest.length; i++) {
            digest[i] = (byte) (i + 1);
        }
        byte[] padded = new byte[128];
        System.arraycopy(digest, 0, padded, 128 - digest.length, digest.length);
        padded[0] = 0; // keep the value below the modulus

        byte[] signature = rsa.decrypt(padded);
        assertTrue(rsa.check(digest, signature));

        byte[] other = digest.clone();
        other[19] ^= 1;
        assertFalse(rsa.check(other, signature));
        // garbage must be "not valid", never an exception
        assertFalse(rsa.check(digest, new byte[300]));
    }
}
