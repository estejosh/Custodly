package group.fungibility.custodly;

import android.os.Environment;
import java.io.File;
import java.nio.charset.StandardCharsets;

/**
 * Finds the Syncthing folder beastly shares, so nobody has to browse for it. It looks for a
 * pairing.json written by custodly-intake. Needs the "All files access" switch, which gives
 * this app no network access: keys can still only leave as sealed files in that folder.
 */
final class Auto {
    private Auto() {}

    static boolean allowed() {
        return Environment.isExternalStorageManager();
    }

    private static boolean isPairingFolder(File dir) {
        File f = new File(dir, "pairing.json");
        try {
            return f.isFile() && f.length() < 4096
                    && new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).contains("custodly-pairing/v1");
        } catch (Exception e) {
            return false;
        }
    }

    private static File[] dirs(File parent) {
        File[] kids = parent.listFiles(File::isDirectory);
        return kids == null ? new File[0] : kids;
    }

    /** The shared folder, or null if Syncthing has not delivered it yet. */
    static File find() {
        File sd = Environment.getExternalStorageDirectory();
        File[] roots = {sd, new File(sd, "Documents"), new File(sd, "Syncthing"), new File(sd, "Documents/ferryman-comms"),
                new File(sd, "Download")};
        for (File root : roots) {
            if (isPairingFolder(root)) return root;
            for (File d : dirs(root)) {
                if (isPairingFolder(d)) return d;
                if (d.getName().startsWith(".") || d.getName().equals("Android")) continue;
                for (File c : dirs(d)) if (isPairingFolder(c)) return c;
            }
        }
        return null;
    }
}
