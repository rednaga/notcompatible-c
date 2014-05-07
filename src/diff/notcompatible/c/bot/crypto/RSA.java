package diff.notcompatible.c.bot.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Simple class for RSA crypto functionality
 */
public class RSA {

    public RSAPrivateKey rsaPrivateKey;
    public RSAPublicKey rsaPublicKey;

    /**
     * Used on initial run - each bot will initialize a new public/private key and send it to the server for further
     * comms
     */
    public void genKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(0x400);
            KeyPair keyPair = kpg.genKeyPair();

            rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    /**
     * Originally called "decode2" though it is a simple decrypt
     * 
     * @param data
     * @return
     */
    public byte[] decrypt(byte[] data) {
        byte[] result = null;

        try {
            // Original Android based code doesn't require the bouncy castle provider as,
            // that is the default for the Android container
            Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            result = cipher.doFinal(data);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        return result;
    }

    /**
     * Originally called "decode" though it clearly encrypts
     * 
     * @param data
     * @return
     */
    public byte[] encrypt(byte[] data) {
        byte[] result = null;

        try {
            // Original Android based code doesn't require the bouncy castle provider as,
            // that is the default for the Android container
            Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            result = cipher.doFinal(data);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        return result;
    }

    /**
     * Eats the "pub" file which contains the public key
     * 
     * @param key
     */
    public void loadKey(File key) {
        try {
            InputStream fi = new FileInputStream(key);
            byte data[] = new byte[fi.available()];

            DataInputStream dis = new DataInputStream(fi);
            dis.read(data);
            dis.close();

            BigInteger pbbi = new BigInteger(1, data);
            BigInteger ex = BigInteger.valueOf(0x10001);

            RSAPublicKeySpec rsaPKS = new RSAPublicKeySpec(pbbi, ex);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rsaPublicKey = (RSAPublicKey) kf.generatePublic(rsaPKS);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Load public key (C&C key) from byte[]
     * 
     * @param data
     * @return
     */
    public boolean loadPublic(byte[] data) {
        try {
            BigInteger mod = new BigInteger(1, data);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, BigInteger.valueOf(0x10001));
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            return true;
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return false;
    }

    /**
     * Perform a check of digest against signature value
     * 
     * @param digest
     * @param signatureValue
     * @return
     */
    public boolean check(byte[] digest, byte[] signatureValue) {
        byte[] dc = encrypt(signatureValue);

        if (dc.length != digest.length) {
            byte[] dst = new byte[digest.length];
            System.arraycopy(dc, dc.length - digest.length, dst, 0, dst.length);
            return Arrays.equals(dst, digest);
        }

        return false;
    }

    public void loadClientPublic(File file) {
        try {
            InputStream fi = new FileInputStream(file);

            byte buffer[] = new byte[fi.available()];

            DataInputStream dis = new DataInputStream(fi);
            dis.read(buffer);
            dis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(buffer);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public void loadClientPrivate(File path) {
        try {
            InputStream fi = new FileInputStream(path);

            byte buffer[] = new byte[fi.available()];

            DataInputStream dis = new DataInputStream(fi);
            dis.read(buffer);
            dis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(buffer);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public void saveClientPublic(File path) {
        try {
            byte[] publicData = rsaPublicKey.getEncoded();
            DataOutputStream file = new DataOutputStream(
                            new FileOutputStream(path.getAbsolutePath() + "/client.public"));
            file.write(publicData);
            file.flush();
            file.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public void saveClientPrivate(File path) {
        try {
            byte[] publicData = rsaPrivateKey.getEncoded();
            DataOutputStream file = new DataOutputStream(new FileOutputStream(path.getAbsolutePath()
                            + "/client.private"));
            file.write(publicData);
            file.flush();
            file.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }
}
