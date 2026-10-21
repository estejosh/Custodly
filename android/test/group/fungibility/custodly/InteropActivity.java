package group.fungibility.custodly;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.security.PrivateKey;
import java.security.Signature;

/** Throwaway test app: runs the phone crypto on a real Android runtime and logs the fixture. */
public class InteropActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            PrivateKey k = DeviceKey.privateKey();
            Log.i("CUSTODLY_DIAG", "key class=" + k.getClass().getName() + " alg=" + k.getAlgorithm() + " fmt=" + k.getFormat());
            for (String n : new String[] {"Ed25519", "EdDSA", "NONEwithEdDSA", "NONEwithECDSA", "Ed25519ph"}) {
                try {
                    Signature s = Signature.getInstance(n);
                    s.initSign(k);
                    s.update(new byte[] {1, 2, 3});
                    Log.i("CUSTODLY_DIAG", n + " OK siglen=" + s.sign().length);
                } catch (Throwable t) {
                    Log.i("CUSTODLY_DIAG", n + " failed: " + t);
                }
            }
            Log.i("CUSTODLY_FIXTURE", "BEGIN" + InteropMain.run(DeviceKey.privateKey(), DeviceKey.publicKey()) + "END");
        } catch (Throwable t) {
            Log.e("CUSTODLY_FIXTURE", "FAILED " + android.util.Log.getStackTraceString(t));
        }
        finish();
    }
}