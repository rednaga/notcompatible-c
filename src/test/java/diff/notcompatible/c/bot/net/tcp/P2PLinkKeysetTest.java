package diff.notcompatible.c.bot.net.tcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

class P2PLinkKeysetTest {

    @Test
    void keysetFillsAllHundredKeyBytes() {
        byte[] keyset = P2PLink.generateRc4Keyset();
        assertEquals(101, keyset.length);
        assertEquals(7, keyset[0]);

        // Regression: this used to write rc4KeysetData[1] on every iteration, leaving bytes 2..100 zero
        // (~8 bits of key). The bot fills all of 1..100, so a real key has far more than a handful of
        // distinct byte values and plenty of non-zero bytes beyond the first.
        Set<Byte> distinct = new HashSet<>();
        int nonZeroAfterFirst = 0;
        for (int i = 1; i < keyset.length; i++) {
            distinct.add(keyset[i]);
            if (i > 1 && keyset[i] != 0) {
                nonZeroAfterFirst++;
            }
        }
        assertTrue(distinct.size() > 30, "distinct key byte values: " + distinct.size());
        assertTrue(nonZeroAfterFirst > 80, "non-zero bytes after the first: " + nonZeroAfterFirst);
    }

    @Test
    void keysetsDiffer() {
        assertTrue(!java.util.Arrays.equals(P2PLink.generateRc4Keyset(), P2PLink.generateRc4Keyset()));
    }
}
