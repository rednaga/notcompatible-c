package diff.notcompatible.c.bot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import diff.notcompatible.c.bot.objects.VariantAConfig;

class VariantAConfigTest {

    // res/raw/data from com.Security.Update (sha256 2c5e656af90044cf5cc694519a42477cb18bd4b2722b1474cdead4a8748d3f70)
    private static final String SAMPLE_A_DATA = "3e34c03b010a61476bec9c523c134319012d9d2c2a8a49d96d67e38306ca8a5e"
                    + "5651cf7441f5c4790b4be887382e20da";

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    void decryptsRealVariantASample() {
        VariantAConfig config = VariantAConfig.decrypt(hex(SAMPLE_A_DATA));
        assertNotNull(config);
        assertEquals("notcompatibleapp.eu", config.server1);
        assertEquals("3na3budet9.ru", config.server2);
        assertEquals(8014, config.port1);
        assertEquals(8014, config.port2);
    }

    @Test
    void rejectsRc4TlvConfigs() throws Exception {
        // The RC4/TLV configs (C/D builds) are not a multiple of the AES block size (253 bytes) and the
        // repo default must never be mistaken for a variant A config either
        Path def = Paths.get("resources/default.config");
        assertNull(VariantAConfig.decrypt(Files.readAllBytes(def)));
    }

    @Test
    void rejectsGarbage() {
        assertNull(VariantAConfig.decrypt(null));
        assertNull(VariantAConfig.decrypt(new byte[0]));
        assertNull(VariantAConfig.decrypt(new byte[16]));
        assertNull(VariantAConfig.decrypt(new byte[15]));
    }
}
