package group.fungibility.custodly;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Custodly phone app. Sends a key to beastly as a sealed file in a Syncthing folder.
 * It has no network permission at all: the only way anything leaves is that folder.
 */
public class MainActivity extends Activity {
    private static final int PICK_FOLDER = 1;
    private SharedPreferences prefs;
    private LinearLayout root;
    private String note = "";

    // what the user typed, kept across re-renders
    private String projectChoice = "";
    private String nameDraft = "";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        prefs = getSharedPreferences("custodly", MODE_PRIVATE);
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(0, insets.getSystemWindowInsetTop(), 0, insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(scroll);
        offerHomeShortcut();
    }

    /** Android never puts a new app on the home screen by itself; ask once to pin it. */
    private void offerHomeShortcut() {
        if (prefs.getBoolean("shortcut_asked", false)) return;
        prefs.edit().putBoolean("shortcut_asked", true).apply();
        try {
            android.content.pm.ShortcutManager sm = getSystemService(android.content.pm.ShortcutManager.class);
            if (sm == null || !sm.isRequestPinShortcutSupported()) return;
            int icon = getResources().getIdentifier("ic_launcher", "mipmap", getPackageName());
            Intent open = new Intent(this, MainActivity.class).setAction(Intent.ACTION_MAIN);
            android.content.pm.ShortcutInfo info = new android.content.pm.ShortcutInfo.Builder(this, "custodly-home")
                .setShortLabel("Custodly")
                .setIcon(android.graphics.drawable.Icon.createWithResource(this, icon))
                .setIntent(open)
                .build();
            sm.requestPinShortcut(info, null);
        } catch (Exception ignored) {
            // the app is still in the app drawer
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    // ------------------------------------------------------------------ state

    private static final class State {
        String error;
        boolean haveFolder;
        byte[] pairingPub;
        String pairingFp;
        boolean pinned;
        boolean haveDevice;
        String deviceStatus; // null = nothing heard yet
        String deviceCode = "";
        String deviceId = "";
        List<String[]> projects = new ArrayList<>(); // id, label
        List<JSONObject> receipts = new ArrayList<>();
    }

    private void refresh() {
        new Thread(() -> {
            State s = compute();
            runOnUiThread(() -> render(s));
        }).start();
    }

    private Saf saf() {
        String path = prefs.getString("sync_path", null);
        if (path != null && Auto.allowed() && new java.io.File(path).isDirectory()) return new Saf(new java.io.File(path));
        String u = prefs.getString("tree_uri", null);
        return u == null ? null : new Saf(this, Uri.parse(u));
    }

    /** If the all-files switch is on, find the shared folder without asking anyone to browse. */
    private void autoFindFolder() {
        if (prefs.getString("sync_path", null) != null || prefs.getString("tree_uri", null) != null) return;
        if (!Auto.allowed()) return;
        java.io.File f = Auto.find();
        if (f != null) prefs.edit().putString("sync_path", f.getAbsolutePath()).apply();
    }

    private State compute() {
        State s = new State();
        autoFindFolder();
        Saf saf = saf();
        s.haveFolder = saf != null;
        if (saf == null) return s;
        try {
            String root = saf.root();
            Map<String, String> top = saf.children(root);
            String pinnedHex = prefs.getString("intake_pub", null);
            s.pinned = pinnedHex != null;
            if (!s.pinned) {
                String f = top.get("pairing.json");
                if (f != null) {
                    JSONObject j = new JSONObject(new String(saf.read(f), "UTF-8"));
                    s.pairingPub = Crypto.unhex(j.getString("intake_pub"));
                    s.pairingFp = Deposit.fingerprint(s.pairingPub);
                    if (s.pairingPub.length != 32) {
                        s.pairingPub = null;
                        s.error = "pairing.json is not valid.";
                    }
                }
                return s;
            }
            s.haveDevice = prefs.getBoolean("enrolled_sent", false) && DeviceKey.exists();
            if (s.haveDevice) {
                byte[] pub = DeviceKey.publicKey();
                s.deviceId = Deposit.deviceId(pub);
                s.deviceCode = Deposit.deviceCode(pub);
                String outbox = top.get("outbox");
                if (outbox != null) {
                    Map<String, String> out = saf.children(outbox);
                    String st = out.get("device-" + s.deviceId + ".json");
                    if (st != null) s.deviceStatus = new JSONObject(new String(saf.read(st), "UTF-8")).optString("status");
                    String pj = out.get("projects.json");
                    if (pj != null) {
                        JSONArray a = new JSONObject(new String(saf.read(pj), "UTF-8")).getJSONArray("projects");
                        for (int i = 0; i < a.length(); i++) {
                            s.projects.add(new String[] {a.getJSONObject(i).getString("id"), a.getJSONObject(i).optString("label")});
                        }
                    }
                    for (Map.Entry<String, String> e : out.entrySet()) {
                        if (!e.getKey().startsWith("receipt-") || !e.getKey().endsWith(".json")) continue;
                        JSONObject r = new JSONObject(new String(saf.read(e.getValue()), "UTF-8"));
                        if (s.deviceId.equals(r.optString("device_id"))) s.receipts.add(r);
                    }
                    Collections.sort(s.receipts, (x, y) -> y.optString("at").compareTo(x.optString("at")));
                }
            }
        } catch (Exception e) {
            s.error = "Could not read the sync folder: " + e.getMessage();
        }
        return s;
    }

    // ----------------------------------------------------------------- render

    private void render(State s) {
        root.removeAllViews();
        head("Custodly");
        if (!note.isEmpty()) {
            body(note);
        }
        if (s.error != null) body(s.error);

        if (!s.haveFolder) {
            if (!Auto.allowed()) {
                body("Step 1 of 3. Custodly finds its Syncthing folder by itself. It only needs the \"All files access\" switch turned on. This app has no internet access at all: keys leave only as encrypted files in that folder.");
                button("Allow file access", () -> startActivity(new Intent(
                        android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName()))));
                button("Or pick the folder by hand", () -> pickFolder());
                return;
            }
            body("Step 1 of 3. Looking for the \"Custodly deposit\" folder from beastly. Open Syncthing on this phone and accept the folder beastly is sharing, then come back here. This page checks again by itself.");
            button("Look again", this::refresh);
            button("Pick the folder by hand", () -> pickFolder());
            return;
        }
        if (!s.pinned) {
            if (s.pairingPub == null) {
                body("Step 2 of 3. Waiting for beastly's pairing file to arrive through Syncthing. Make sure Syncthing is running on this phone and beastly is on.");
                button("Check again", this::refresh);
                button("Choose a different folder", this::forgetFolder);
                return;
            }
            body("Step 2 of 3. Beastly's key fingerprint is:");
            big(s.pairingFp);
            body("Open the Custodly portal on beastly (or run custodly-intake status). If it shows exactly the same fingerprint, trust it.");
            button("It matches. Trust beastly", () -> {
                prefs.edit().putString("intake_pub", Crypto.hex(s.pairingPub)).apply();
                note = "";
                refresh();
            });
            button("It does not match", this::forgetFolder);
            return;
        }
        if (!s.haveDevice) {
            body("Step 3 of 3. Registering this phone with beastly.");
            button("Register this phone", this::enrollDevice);
            return;
        }
        if (!"enrolled".equals(s.deviceStatus)) {
            if ("rejected".equals(s.deviceStatus)) {
                body("Beastly refused this phone. Reset it below to start over.");
            } else {
                body("Waiting for you to approve this phone on beastly. In the portal, find this phone and type this code:");
                big(spaced(s.deviceCode));
                body("If nothing happens, check that Syncthing has synced.");
            }
            button("Check again", this::refresh);
            button("Send registration again", this::enrollDevice);
            resetButton();
            return;
        }
        mainScreen(s);
    }

    private void mainScreen(State s) {
        label("What is it for?");
        EditText forWhat = field("e.g. deepseek for redaktly", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        forWhat.setText(projectChoice);
        root.addView(forWhat);
        if (!s.projects.isEmpty()) {
            StringBuilder known = new StringBuilder("Beastly knows: ");
            for (int i = 0; i < s.projects.size(); i++) {
                String[] p = s.projects.get(i);
                known.append(i > 0 ? ", " : "").append(p[1].isEmpty() ? p[0] : p[1]);
            }
            body(known.toString());
        }

        label("Name (optional, worked out if empty)");
        EditText name = field("e.g. OPENROUTER_API_KEY", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        name.setText(nameDraft);
        root.addView(name);

        label("Key");
        EditText value = field("paste or type the key", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        value.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        root.addView(value);
        button("Paste from clipboard, then clear it", () -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData d = cm.getPrimaryClip();
            if (d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null) {
                value.setText(d.getItemAt(0).getText().toString().trim());
                cm.clearPrimaryClip();
            }
        });

        button("Send to beastly", () -> {
            String forText = forWhat.getText().toString().trim();
            String n = name.getText().toString().trim().toUpperCase(java.util.Locale.ROOT).replace('-', '_').replace('.', '_');
            String v = value.getText().toString();
            projectChoice = forText;
            nameDraft = n;
            if (forText.isEmpty() || forText.length() > 120) { note = "Say what the key is for (a few words)."; render(s); return; }
            if (!n.isEmpty() && !n.matches("[A-Z][A-Z0-9_]{0,63}")) { note = "The name must start with a letter and use only letters, digits and _ (e.g. DEEPSEEK_API_KEY)."; render(s); return; }
            if (v.isEmpty() || v.length() > 16000) { note = "Enter the key (up to 16 KB)."; render(s); return; }
            sendDeposit(forText, n, v);
        });

        head2("Or ask Custodly to get a key");
        body("Beastly works out exactly what it would create and sends it back here for you to approve. Nothing is made until you do.");
        EditText svc = field("service, e.g. openrouter", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        root.addView(svc);
        EditText reqFor = field("for which project, e.g. redaktly", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        root.addView(reqFor);
        EditText hours = field("lifetime in hours (24)", InputType.TYPE_CLASS_NUMBER);
        root.addView(hours);
        EditText budget = field("spend cap in dollars", InputType.TYPE_CLASS_NUMBER);
        root.addView(budget);
        button("Request a key", () -> {
            String sv = svc.getText().toString().trim();
            String rf = reqFor.getText().toString().trim();
            int h = hours.getText().toString().trim().isEmpty() ? 24 : parseInt(hours.getText().toString());
            int b = parseInt(budget.getText().toString());
            if (sv.isEmpty() || rf.isEmpty()) { note = "Say which service and which project."; render(s); return; }
            if (h < 1 || h > 720) { note = "Lifetime must be 1 to 720 hours."; render(s); return; }
            if (b < 1 || b > 1000) { note = "Enter a spend cap from 1 to 1000 dollars."; render(s); return; }
            sendRequest(sv, rf, h, b);
        });

        head2("Recent");
        JSONArray sent = sentList();
        int shown = 0;
        for (int i = sent.length() - 1; i >= 0 && shown < 8; i--, shown++) {
            JSONObject it = sent.optJSONObject(i);
            String id = it.optString("id");
            String status = "waiting for beastly...";
            for (JSONObject r : s.receipts) {
                if (id.equals(r.optString("id"))) {
                    String st = r.optString("status");
                    String mark = st.equals("delivered") ? "DELIVERED" : st.equals("rejected") ? "REJECTED"
                        : st.equals("needs_approval") ? "WAITING FOR YOUR APPROVAL" : st.equals("denied") ? "DENIED"
                        : st.equals("failed") ? "FAILED" : "NOT DELIVERED";
                    if (st.equals("needs_approval")) { pendingDigest = r.optString("digest"); pendingId = id; } else { pendingDigest = ""; }
                    status = mark + (r.optString("detail").isEmpty() ? "" : ": " + r.optString("detail"));
                    String chk = r.optString("check");
                    if (!chk.isEmpty()) {
                        String word = chk.equals("valid") ? "Test passed" : chk.equals("invalid") ? "Test FAILED"
                            : chk.equals("error") ? "Test inconclusive" : "Not tested";
                        status += "\n" + word + (r.optString("check_detail").isEmpty() ? "" : ": " + r.optString("check_detail"));
                    }
                    if (!r.optString("purpose").isEmpty()) status += "\nFor: " + r.optString("purpose");
                }
            }
            body((it.optString("name").isEmpty() ? "Key" : it.optString("name")) + " for " + it.optString("project") + "\n" + status);
            if (!pendingDigest.isEmpty()) {
                final String rid = pendingId, dg = pendingDigest;
                button("Approve exactly this", () -> sendAnswer(true, rid, dg));
                button("Deny", () -> sendAnswer(false, rid, dg));
                pendingDigest = "";
            }
        }
        if (shown == 0) body("Nothing sent yet.");
        button("Refresh", this::refresh);
        resetButton();
    }

    // ---------------------------------------------------------------- actions

    private String pendingDigest = "";
    private String pendingId = "";

    private static int parseInt(String s) {
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return -1; }
    }

    private void sendRequest(String service, String forText, int hours, int budget) {
        new Thread(() -> {
            String msg;
            try {
                Saf saf = saf();
                byte[] intakePub = Crypto.unhex(prefs.getString("intake_pub", ""));
                String id = Crypto.hex(Crypto.random(16));
                String file = Deposit.request(intakePub, DeviceKey.privateKey(), DeviceKey.publicKey(), service, forText,
                        hours, budget, id, Deposit.now());
                saf.write(saf.ensureDir(saf.root(), "inbox"), "dep-" + id + ".json", Crypto.utf8(file));
                JSONArray sent = sentList();
                sent.put(new JSONObject().put("id", id).put("name", "Request: " + service).put("project", forText));
                prefs.edit().putString("sent", sent.toString()).apply();
                msg = "Asked for a key. Beastly will send back what it would create for you to approve.";
            } catch (Exception e) {
                msg = "Could not ask: " + e.getMessage();
            }
            final String shown = msg;
            runOnUiThread(() -> { note = shown; refresh(); });
        }).start();
    }

    private void sendAnswer(boolean approve, String requestId, String digest) {
        new Thread(() -> {
            String msg;
            try {
                Saf saf = saf();
                byte[] intakePub = Crypto.unhex(prefs.getString("intake_pub", ""));
                String id = Crypto.hex(Crypto.random(16));
                String file = Deposit.answer(intakePub, DeviceKey.privateKey(), DeviceKey.publicKey(), approve,
                        requestId, digest, id, Deposit.now());
                saf.write(saf.ensureDir(saf.root(), "inbox"), "dep-" + id + ".json", Crypto.utf8(file));
                msg = approve ? "Approved. Waiting for beastly to create and deliver it." : "Denied. Nothing will be created.";
            } catch (Exception e) {
                msg = "Could not answer: " + e.getMessage();
            }
            final String shown = msg;
            runOnUiThread(() -> { note = shown; refresh(); });
        }).start();
    }

    private void sendDeposit(String project, String name, String value) {
        new Thread(() -> {
            String msg;
            try {
                Saf saf = saf();
                byte[] intakePub = Crypto.unhex(prefs.getString("intake_pub", ""));
                byte[] devicePub = DeviceKey.publicKey();
                java.security.PrivateKey sk = DeviceKey.privateKey();
                String id = Crypto.hex(Crypto.random(16));
                String file = Deposit.seal(intakePub, sk, devicePub, project, name, value, null, id, Deposit.now());
                String inbox = saf.ensureDir(saf.root(), "inbox");
                saf.write(inbox, "dep-" + id + ".json", Crypto.utf8(file));
                JSONArray sent = sentList();
                sent.put(new JSONObject().put("id", id).put("name", name).put("project", project));
                prefs.edit().putString("sent", sent.toString()).apply();
                msg = "Sent " + name + ". It leaves this phone when Syncthing syncs.";
                nameDraft = "";
            } catch (Exception e) {
                msg = "Could not send: " + e.getMessage();
            }
            final String shown = msg;
            runOnUiThread(() -> { note = shown; refresh(); });
        }).start();
    }

    private void enrollDevice() {
        new Thread(() -> {
            String msg = "";
            try {
                byte[] pub = DeviceKey.publicKey();
                Saf saf = saf();
                String inbox = saf.ensureDir(saf.root(), "inbox");
                String name = Build.MODEL == null ? "Android phone" : Build.MODEL;
                saf.write(inbox, "enroll-" + Deposit.deviceId(pub) + ".json",
                        Crypto.utf8(Deposit.enrollJson(pub, name, Deposit.now())));
                prefs.edit().putBoolean("enrolled_sent", true).apply();
            } catch (Exception e) {
                msg = "Could not register: " + e.getMessage();
            }
            final String shown = msg;
            runOnUiThread(() -> { note = shown; refresh(); });
        }).start();
    }

    private void pickFolder() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(i, PICK_FOLDER);
    }

    private void forgetFolder() {
        prefs.edit().remove("sync_path").remove("tree_uri").remove("intake_pub").apply();
        note = "";
        refresh();
    }

    private void resetButton() {
        button("Reset this phone", () -> new AlertDialog.Builder(this)
                .setTitle("Reset this phone?")
                .setMessage("It forgets the folder, beastly's key and this phone's identity. You will need to approve it on beastly again.")
                .setPositiveButton("Reset", (d, w) -> {
                    try { DeviceKey.delete(); } catch (Exception ignored) { }
                    prefs.edit().clear().apply(); note = ""; refresh(); })
                .setNegativeButton("Cancel", null)
                .show());
    }

    private JSONArray sentList() {
        try {
            return new JSONArray(prefs.getString("sent", "[]"));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == PICK_FOLDER && result == RESULT_OK && data != null && data.getData() != null) {
            Uri u = data.getData();
            getContentResolver().takePersistableUriPermission(u,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            prefs.edit().putString("tree_uri", u.toString()).apply();
        }
    }

    // --------------------------------------------------------------- ui bits

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private static String spaced(String code) {
        return code.length() == 6 ? code.substring(0, 3) + " " + code.substring(3) : code;
    }

    private void head(String t) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(28);
        v.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(v);
    }

    private void head2(String t) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(20);
        v.setTypeface(Typeface.DEFAULT_BOLD);
        v.setPadding(0, dp(24), 0, dp(4));
        root.addView(v);
    }

    private void body(String t) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(16);
        v.setPadding(0, dp(10), 0, dp(4));
        root.addView(v);
    }

    private void label(String t) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(14);
        v.setPadding(0, dp(16), 0, 0);
        root.addView(v);
    }

    private void big(String t) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(34);
        v.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        v.setGravity(Gravity.CENTER);
        v.setPadding(0, dp(16), 0, dp(16));
        root.addView(v);
    }

    private EditText field(String hint, int type) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true); // must come first: it resets the input type
        e.setInputType(type);
        e.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return e;
    }

    private void button(String t, Runnable r) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setOnClickListener(v -> r.run());
        root.addView(b);
    }
}