package group.fungibility.custodly;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

/** This phone's Ed25519 identity, held by the Android keystore so the private key can never be read out. */
final class DeviceKey {
    private static final String ALIAS = "custodly_device";

    private DeviceKey() {}

    private static KeyStore store() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    static boolean exists() throws Exception {
        return store().containsAlias(ALIAS);
    }

    /** Raw 32-byte public key; creates the key on first use. */
    static byte[] publicKey() throws Exception {
        KeyStore ks = store();
        if (!ks.containsAlias(ALIAS)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            g.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("ed25519"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                    .build());
            g.generateKeyPair();
        }
        return Crypto.tail32(ks.getCertificate(ALIAS).getPublicKey().getEncoded());
    }

    static PrivateKey privateKey() throws Exception {
        publicKey(); // creates the key if this is the first use
        return (PrivateKey) store().getKey(ALIAS, null);
    }

    static void delete() throws Exception {
        KeyStore ks = store();
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
    }
}