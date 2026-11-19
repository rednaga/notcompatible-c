package diff.notcompatible.c.bot.objects;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Config for the old "variant A" bot (com.Security.Update, 2012), which predates the RC4/TLV
 * "Packet" config used by the later builds (see {@link Config}).
 *
 * res/raw/data is AES-256-ECB (NoPadding) with key = SHA-256("ZTY4MGE5YQo"); the plaintext is a
 * NUL-padded ASCII string "Server1|Server2|Port1|Port2". If a port is missing the bot falls
 * back to 8014 (0x1f4e) in getPort().
 */
public class VariantAConfig {

    public static final String PASSKEY = "ZTY4MGE5YQo";

    public final String server1;
    public final String server2;
    public final int port1;
    public final int port2;

    public VariantAConfig(String server1, String server2, int port1, int port2) {
        this.server1 = server1;
        this.server2 = server2;
        this.port1 = port1;
        this.port2 = port2;
    }

    /**
     * @return the parsed config, or null if the blob is not a variant A config (wrong length,
     *         not decryptable, or the plaintext is not "host|host|port|port")
     */
    public static VariantAConfig decrypt(byte[] data) {
        if (data == null || data.length == 0 || data.length % 16 != 0) {
            return null;
        }

        try {
            byte[] key = MessageDigest.getInstance("SHA-256").digest(PASSKEY.getBytes(StandardCharsets.US_ASCII));
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            byte[] plain = cipher.doFinal(data);

            int end = 0;
            while (end < plain.length && plain[end] != 0) {
                end++;
            }
            String[] parts = new String(plain, 0, end, StandardCharsets.US_ASCII).split("\\|", -1);
            if (parts.length != 4) {
                return null;
            }
            for (int i = 0; i < 2; i++) {
                // Keep the "is this really a config" check strict, we guess at the format
                // before trying the other (RC4/TLV) config format
                if (!parts[i].matches("[A-Za-z0-9._-]*")) {
                    return null;
                }
            }
            return new VariantAConfig(parts[0], parts[1], Integer.parseInt(parts[2]), Integer.parseInt(parts[3]));
        } catch (Exception exception) {
            return null;
        }
    }
}
