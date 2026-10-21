package group.fungibility.custodly;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Only the platform's own crypto (JCA): X25519, HKDF-SHA256, ChaCha20-Poly1305, Ed25519. No libraries. */
final class Crypto {
    private static final byte[] X25519_SPKI = unhex("302a300506032b656e032100");
    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {}

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) {
            s.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        }
        return s.toString();
    }

    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4) | Character.digit(s.charAt(2 * i + 1), 16));
        }
        return b;
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    static byte[] tail32(byte[] encoded) {
        byte[] t = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, t, 0, 32);
        return t;
    }

    static byte[] sha256(byte[] in) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(data);
    }

    /** HKDF-SHA256 with a 32-byte output (one expand block). */
    static byte[] hkdf32(byte[] ikm, byte[] salt, byte[] info) throws GeneralSecurityException {
        byte[] prk = hmac(salt, ikm);
        return hmac(prk, concat(info, new byte[] {1}));
    }

    // ---- X25519 ----

    static KeyPair generateX25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    static PublicKey x25519Public(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI, raw)));
    }

    static byte[] ecdh(PrivateKey priv, PublicKey pub) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    // ---- ChaCha20-Poly1305 (RFC 8439, 12-byte nonce, tag appended) ----

    static byte[] chachaSeal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        c.updateAAD(aad);
        return c.doFinal(plaintext);
    }

    // ---- Ed25519 ----

    static byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(message);
        return s.sign();
    }
}