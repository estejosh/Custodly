package group.fungibility.custodly;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

/** Prints a fixture the Rust opener must accept (crates/custodly-intake/tests/fixtures). */
public class InteropMain {
    /** Desktop JDK run: writes the fixture to args[0]. */
    public static void main(String[] args) throws Exception {
        KeyPair device = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String out = run(device.getPrivate(), Crypto.tail32(device.getPublic().getEncoded()));
        java.nio.file.Files.write(java.nio.file.Paths.get(args[0]), out.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** JSON string with every non-ASCII char written as a unicode escape, so the fixture survives any console. */
    static String ascii(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : Deposit.json(s).toCharArray()) {
            if (c < 128) b.append(c); else b.append(String.format("\\u%04x", (int) c));
        }
        return b.toString();
    }

    public static String run(PrivateKey deviceKey, byte[] devicePub) throws Exception {
        KeyPair intake = Crypto.generateX25519();
        byte[] intakePub = Crypto.tail32(intake.getPublic().getEncoded());
        byte[] intakeSecret = Crypto.tail32(intake.getPrivate().getEncoded());
        String created = "2026-10-08T12:00:00Z";
        String value = "sk-or-v1-interop-\u00fcn\u00ef \"quoted\" \\ end";
        String deposit = Deposit.seal(intakePub, deviceKey, devicePub, "custodly",
                "OPENROUTER_API_KEY", value, "openrouter", "00112233445566778899aabbccddeeff", created);
        return "{\"intake_secret\":\"" + Crypto.hex(intakeSecret) + "\",\"device_pub\":\""
                + Crypto.hex(devicePub) + "\",\"created\":\"" + created + "\",\"fingerprint\":\""
                + Deposit.fingerprint(intakePub) + "\",\"device_code\":\"" + Deposit.deviceCode(devicePub)
                + "\",\"expect_value\":" + ascii(value) + ",\"deposit\":" + deposit + "}";
    }
}