package group.fungibility.custodly;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/** Builds the files described in docs/PHONE-DEPOSIT.md (custodly-deposit/v1). */
final class Deposit {
    static final String VERSION = "custodly-deposit/v1";

    private Deposit() {}

    static String fingerprintCompact(byte[] intakePub) throws GeneralSecurityException {
        return Crypto.hex(Crypto.sha256(intakePub)).substring(0, 12);
    }

    static String fingerprint(byte[] intakePub) throws GeneralSecurityException {
        String h = fingerprintCompact(intakePub);
        return h.substring(0, 4) + "-" + h.substring(4, 8) + "-" + h.substring(8, 12);
    }

    static String deviceId(byte[] devicePub) throws GeneralSecurityException {
        return Crypto.hex(Crypto.sha256(devicePub)).substring(0, 16);
    }

    /** Six digits, shown here and in the portal for the same device key. */
    static String deviceCode(byte[] devicePub) throws GeneralSecurityException {
        byte[] h = Crypto.sha256(devicePub);
        long n = (((h[0] & 0xffL) << 24) | ((h[1] & 0xffL) << 16) | ((h[2] & 0xffL) << 8) | (h[3] & 0xffL)) % 1_000_000L;
        return String.format(Locale.ROOT, "%06d", n);
    }

    static String now() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }

    static String json(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format(Locale.ROOT, "\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    static String enrollJson(byte[] devicePub, String name, String created) throws GeneralSecurityException {
        return "{\"v\":\"custodly-enroll/v1\",\"device_id\":" + json(deviceId(devicePub))
                + ",\"device_pub\":" + json(Crypto.hex(devicePub))
                + ",\"name\":" + json(name) + ",\"created\":" + json(created) + "}";
    }

    /** Seal and sign one deposit; returns the file's JSON text. */
    static String seal(byte[] intakePub, PrivateKey deviceKey, byte[] devicePub, String project, String name,
            String value, String provider, String id, String created) throws GeneralSecurityException {
        String plain = "{\"project\":" + json(project) + ",\"name\":" + json(name) + ",\"value\":" + json(value)
                + (provider == null ? "" : ",\"provider\":" + json(provider)) + "}";
        return sealPlain(intakePub, deviceKey, devicePub, plain, id, created);
    }

    /** Ask beastly to mint a key. Carries no secret. */
    static String request(byte[] intakePub, PrivateKey deviceKey, byte[] devicePub, String service, String forText,
            int ttlHours, int budgetUsd, String id, String created) throws GeneralSecurityException {
        String plain = "{\"kind\":\"request\",\"project\":" + json(forText) + ",\"provider\":" + json(service)
                + ",\"ttl_hours\":" + ttlHours + ",\"budget_usd\":" + budgetUsd + "}";
        return sealPlain(intakePub, deviceKey, devicePub, plain, id, created);
    }

    /** Answer a proposal beastly sent back; the digest binds the answer to exactly that proposal. */
    static String answer(byte[] intakePub, PrivateKey deviceKey, byte[] devicePub, boolean approve,
            String requestId, String digest, String id, String created) throws GeneralSecurityException {
        String plain = "{\"kind\":" + json(approve ? "approve" : "deny") + ",\"name\":" + json(requestId)
                + ",\"note\":" + json(digest) + "}";
        return sealPlain(intakePub, deviceKey, devicePub, plain, id, created);
    }

    private static String sealPlain(byte[] intakePub, PrivateKey deviceKey, byte[] devicePub, String plain,
            String id, String created) throws GeneralSecurityException {
        String did = deviceId(devicePub);
        String fp = fingerprintCompact(intakePub);

        KeyPair eph = Crypto.generateX25519();
        byte[] ephPub = Crypto.tail32(eph.getPublic().getEncoded());
        byte[] shared = Crypto.ecdh(eph.getPrivate(), Crypto.x25519Public(intakePub));
        byte[] key = Crypto.hkdf32(shared, Crypto.concat(ephPub, intakePub), Crypto.utf8(VERSION));

        byte[] nonce = Crypto.random(12);
        String aad = VERSION + "\n" + id + "\n" + did + "\n" + created + "\n" + fp;
        byte[] ct = Crypto.chachaSeal(key, nonce, Crypto.utf8(aad), Crypto.utf8(plain));

        String ephHex = Crypto.hex(ephPub);
        String nonceHex = Crypto.hex(nonce);
        String ctHex = Crypto.hex(ct);
        byte[] sig = Crypto.sign(deviceKey, Crypto.utf8(aad + "\n" + ephHex + "\n" + nonceHex + "\n" + ctHex));

        return "{\"v\":" + json(VERSION) + ",\"id\":" + json(id) + ",\"device_id\":" + json(did)
                + ",\"created\":" + json(created) + ",\"intake_fp\":" + json(fp)
                + ",\"eph_pub\":" + json(ephHex) + ",\"nonce\":" + json(nonceHex)
                + ",\"ct\":" + json(ctHex) + ",\"sig\":" + json(Crypto.hex(sig)) + "}";
    }
}