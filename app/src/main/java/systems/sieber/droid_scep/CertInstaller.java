package systems.sieber.droid_scep;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;

import androidx.work.Worker;
import androidx.work.WorkerParameters;

import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

public class CertInstaller extends Worker {

    static String TAG = "CertInstaller";

    DevicePolicyManager mPolicyManager;
    SharedPreferences sharedPrefTemp;

    public CertInstaller(Context context, WorkerParameters params) {
        super(context, params);

        Context c = getApplicationContext();
        sharedPrefTemp = c.getSharedPreferences(MainActivity.SHARED_PREF_TEMP_STORE, Context.MODE_PRIVATE);
    }

    @Override
    public Result doWork() {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Log.w(TAG, "Auto enrollment is only supported on API level 21 or higher.");
            return Result.failure();
        }

        Context c = getApplicationContext();
        RestrictionsManager restrictionsMgr = (RestrictionsManager) c.getSystemService(Context.RESTRICTIONS_SERVICE);
        Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
        int renewDays = appRestrictions.getInt("renew-days", Integer.parseInt(c.getString(R.string.default_renew_days)));
        String url = appRestrictions.getString("scep-url");
        String alias = appRestrictions.getString("keystore-alias");
        String caFingerprint = appRestrictions.getString("ca-fingerprint");
        String subjectDn = appRestrictions.getString("subject-dn");
        String upn = appRestrictions.getString("upn");
        String enrollmentChallenge = appRestrictions.getString("enrollment-challenge", "");
        String enrollmentProfile = appRestrictions.getString("enrollment-profile", "");
        int rsaKeyLenInt = appRestrictions.getInt("rsa-key-length", Integer.parseInt(c.getString(R.string.default_rsa_len)));

        if(!appRestrictions.getBoolean("auto-enroll", false)
                || url == null || url.isEmpty()
                || subjectDn == null || subjectDn.isEmpty()
                || alias == null || alias.isEmpty()) {
            Log.i(TAG, "No auto enroll: disabled or config missing");
            return Result.success();
        }

        Log.d(TAG, "Starting work...");
        mPolicyManager = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
        // mPolicyManager.hasKeyPair(alias) requires API level 31...
        X509Certificate[] chain = null;
        try {
            chain = KeyChain.getCertificateChain(c, alias);
        } catch(KeyChainException | InterruptedException e) {
            Log.d(TAG, e.getMessage());
            //return Result.failure();
        }
        if(chain != null && chain.length > 0 && renewDays > 0) {
            // check if existing cert needs renewal
            long expiresInDays = TimeUnit.DAYS.convert(chain[0].getNotAfter().getTime() - (new Date()).getTime(), TimeUnit.MILLISECONDS);
            if(expiresInDays < renewDays) {
                // request or poll new cert
                requestScep(url, subjectDn, upn, enrollmentChallenge, caFingerprint, enrollmentProfile, rsaKeyLenInt, alias);
            } else {
                Log.i(TAG, alias+" expires on "+chain[0].getNotAfter().toString());
            }
        } else {
            // request or poll new cert
            requestScep(url, subjectDn, upn, enrollmentChallenge, caFingerprint, enrollmentProfile, rsaKeyLenInt, alias);
        }

        // indicate whether the work finished successfully with the Result
        return Result.success();
    }

    private void requestScep(String url, String dn, String upn, String challenge, String caFingerprint, String profile, int keyLength, String alias) {
        try {
            String pendingCert = sharedPrefTemp.getString("cert", "");
            String pendingKey = sharedPrefTemp.getString("key", "");
            String pendingTid = sharedPrefTemp.getString("tid", "");
            if(pendingCert.isEmpty()
                    || pendingKey.isEmpty()
                    || pendingTid.isEmpty()) {
                Log.i(TAG, "Requesting new cert");
                ScepClient.CertReqResponse r = ScepClient.CertReq(url, dn, upn, challenge, caFingerprint, profile, keyLength);
                installKeyPair(alias, r.mPrivKey, r.mCertStore);
            } else {
                Log.i(TAG, "Polling pending cert");
                ScepClient.CertReqResponse r = ScepClient.CertPoll(url, pendingCert, pendingKey, dn, pendingTid);
                installKeyPair(alias, r.mPrivKey, r.mCertStore);
            }

        } catch(ScepClient.RequestPendingException e) {
            Log.w(TAG, "Cert request is (still) pending...");
            SharedPreferences.Editor editor = sharedPrefTemp.edit();
            editor.putString("cert", e.getCertPem());
            editor.putString("key", e.getKeyPem());
            editor.putString("tid", e.getTransactionId());
            editor.apply();

        } catch(Exception e) {
            Log.e(TAG, e.getClass() + ": " + e.getMessage());
        }
    }

    // this function installs a user cert silently without prompt
    // @throws SecurityException if delegated scope CERT_INSTALL is missing
    private boolean installKeyPair(String alias, PrivateKey privKey, CertStore certStore) throws SecurityException, RuntimeException, CertStoreException {
        Collection<? extends Certificate> certs = certStore.getCertificates(null);

        @SuppressWarnings("unchecked")
        Iterator<Certificate> ir = (Iterator<Certificate>) certs.iterator();
        Certificate cert = null;
        while(ir.hasNext()) {
            cert = ir.next();
            System.out.println(cert);
        }
        if(cert == null) throw new RuntimeException("No certificate found in response!");

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            int flags = DevicePolicyManager.INSTALLKEY_REQUEST_CREDENTIALS_ACCESS | DevicePolicyManager.INSTALLKEY_SET_USER_SELECTABLE;
            return mPolicyManager.installKeyPair(
                    null,
                    privKey,
                    new Certificate[]{cert},
                    alias,
                    flags
            );
        } else if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return mPolicyManager.installKeyPair(
                    null,
                    privKey,
                    new Certificate[]{cert},
                    alias,
                    true
            );
        } else if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            /* This effectively prevents the app from using its own certificate, so certificate based
             * authentication can only really work on Android 6+. The certificate chooser is currently
             * never shown on devices that are enrolled */
            return mPolicyManager.installKeyPair(
                    null,
                    privKey,
                    cert,
                    alias
            );
        }

        return false;
    }

}
