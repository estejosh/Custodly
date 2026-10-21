package group.fungibility.custodly;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads and writes the one sync folder. Either a folder the user picked (Android's folder-access API),
 * or, once the user has flipped the one all-files switch, a plain directory found automatically.
 */
final class Saf {
    private final ContentResolver res;
    private final Uri tree;
    private final java.io.File base;

    Saf(Context c, Uri tree) {
        this.res = c.getContentResolver();
        this.tree = tree;
        this.base = null;
    }

    /** Direct file access; document ids are absolute paths. */
    Saf(java.io.File dir) {
        this.res = null;
        this.tree = null;
        this.base = dir;
    }

    String root() {
        return base != null ? base.getAbsolutePath() : DocumentsContract.getTreeDocumentId(tree);
    }

    private Uri doc(String docId) {
        return DocumentsContract.buildDocumentUriUsingTree(tree, docId);
    }

    /** name -> document id for the direct children of a folder. */
    Map<String, String> children(String parentId) {
        Map<String, String> out = new LinkedHashMap<>();
        if (base != null) {
            java.io.File[] kids = new java.io.File(parentId).listFiles();
            if (kids != null) for (java.io.File k : kids) out.put(k.getName(), k.getAbsolutePath());
            return out;
        }
        Uri kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId);
        try (Cursor c = res.query(kids, new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME},
                null, null, null)) {
            while (c != null && c.moveToNext()) out.put(c.getString(1), c.getString(0));
        } catch (RuntimeException e) {
            // folder missing or permission gone: caller sees an empty listing
        }
        return out;
    }

    String child(String parentId, String name) {
        return children(parentId).get(name);
    }

    String ensureDir(String parentId, String name) throws IOException {
        String have = child(parentId, name);
        if (have != null) return have;
        if (base != null) {
            java.io.File d = new java.io.File(parentId, name);
            if (!d.isDirectory() && !d.mkdirs()) throw new IOException("could not create folder " + name);
            return d.getAbsolutePath();
        }
        try {
            Uri made = DocumentsContract.createDocument(res, doc(parentId), DocumentsContract.Document.MIME_TYPE_DIR, name);
            if (made == null) throw new IOException("could not create folder " + name);
            return DocumentsContract.getDocumentId(made);
        } catch (java.io.FileNotFoundException e) {
            throw new IOException("could not create folder " + name, e);
        }
    }

    byte[] read(String docId) throws IOException {
        if (base != null) return java.nio.file.Files.readAllBytes(new java.io.File(docId).toPath());
        try (InputStream in = res.openInputStream(doc(docId))) {
            if (in == null) throw new IOException("cannot open file");
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) o.write(buf, 0, n);
            return o.toByteArray();
        }
    }

    /** Create the file, or overwrite it if the name already exists. */
    void write(String parentId, String name, byte[] data) throws IOException {
        if (base != null) {
            // write beside, then rename, so Syncthing never syncs a half-written file
            java.io.File tmp = new java.io.File(parentId, "." + name + ".tmp");
            java.nio.file.Files.write(tmp.toPath(), data);
            java.nio.file.Files.move(tmp.toPath(), new java.io.File(parentId, name).toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return;
        }
        String existing = child(parentId, name);
        Uri target = existing != null ? doc(existing)
                : DocumentsContract.createDocument(res, doc(parentId), "application/octet-stream", name);
        if (target == null) throw new IOException("could not create " + name);
        try (OutputStream out = res.openOutputStream(target, "wt")) {
            if (out == null) throw new IOException("cannot write " + name);
            out.write(data);
        }
    }
}