package diff.notcompatible.c.bot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import diff.notcompatible.c.bot.objects.HubList;
import diff.notcompatible.c.bot.objects.HubListItem;
import diff.notcompatible.c.bot.objects.MyBuffer;
import diff.notcompatible.c.bot.objects.Packet;

/**
 * Behaviour that was checked against the reversed samples (com.security.patch,
 * com.core.android.defender) and had been reconstructed wrongly here.
 */
class SampleParityTest {

    @Test
    void clearExpiredDeletesUnusedFailedEntriesOnly() {
        long now = System.currentTimeMillis();
        HubList hubs = new HubList();

        HubListItem failed = hubs.add();
        failed.ip = "10.0.0.1";
        failed.used = false;
        failed.status = -1;
        failed.lastConnect = now;

        HubListItem inUse = hubs.add();
        inUse.ip = "10.0.0.2";
        inUse.used = true;
        inUse.status = -1;
        inUse.lastConnect = now;

        HubListItem good = hubs.add();
        good.ip = "10.0.0.3";
        good.used = false;
        good.status = 1;
        good.lastConnect = now;

        hubs.clearExpired();

        // The bot deletes (unused && status == -1 && lastConnect - 0x65813800 < now)
        assertEquals(2, hubs.count());
        assertEquals("10.0.0.2", hubs.getByIndex(0).ip);
        assertEquals("10.0.0.3", hubs.getByIndex(1).ip);
    }

    @Test
    void unpackAcceptsMinimumSizedPacket() {
        // dword size = 5, then a tag-length byte of 0: smallest thing the bot's Size >= 5 check accepts
        MyBuffer buffer = new MyBuffer();
        buffer.putDword(5);
        buffer.put((byte) 0);
        Packet packet = Packet.unpack(buffer);
        assertNotNull(packet);
        assertEquals("", packet.tag);
    }
}
