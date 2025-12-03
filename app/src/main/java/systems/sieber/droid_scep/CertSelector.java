package systems.sieber.droid_scep;

import android.annotation.SuppressLint;
import android.app.admin.DelegatedAdminReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;

import androidx.annotation.NonNull;


@SuppressLint("NewApi")
public class CertSelector extends DelegatedAdminReceiver {

    private static final String TAG = "CertSelector";

    private Context context;

    public String onChoosePrivateKeyAlias(Context c, @NonNull Intent intent, int uid, Uri uri, String alias) {
        this.context = c;
        PackageManager pm = c.getPackageManager();
        String packageName = pm.getNameForUid(uid);
        String strUri = Uri.decode(String.valueOf(uri)).replace("/", "");
        RestrictionsManager rm = (RestrictionsManager) c.getSystemService(Context.RESTRICTIONS_SERVICE);
        Bundle bundle = rm.getApplicationRestrictions();
        boolean deny = bundle.getBoolean("auto_deny");
        Parcelable[] mapping = bundle.getParcelableArray("cert_mapping");
        if(packageName != null) {
            Log.d(TAG, packageName+" receiving request " + alias + "/" + strUri);
            if(mapping != null) {
                for(Parcelable parcelable : mapping) {
                    Bundle rule = (Bundle) parcelable;
                    if(rule.getString("appid").equals(packageName)
                        && (
                            rule.getString("uri").equals(strUri)
                            || rule.getString("uri").equals("*")
                            || rule.getString("uri").isEmpty()
                        )
                    ) {
                        Log.i(TAG, packageName+" preselected: " + rule.getString("certalias"));
                        return String.valueOf(rule.getString("certalias"));
                    }
                }
            }
            if(deny) {
                Log.e(TAG, packageName+" denied");
                return "android:alias-selection-denied";
            }
            Log.e(TAG, packageName+" default");
            return null;
        }
        Log.e(TAG, "received unknown request for " + alias);
        return null;
    }

}
