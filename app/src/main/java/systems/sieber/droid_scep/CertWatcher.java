package systems.sieber.droid_scep;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.media.RingtoneManager;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.work.ListenableWorker;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class CertWatcher extends Worker {

    static String TAG = "CertExpiryCheck";

    static String CHANNEL_ID = "cert_expiration_check";
    static CharSequence CHANNEL_NAME = "Cert Expiration Check";

    public CertWatcher(Context context, WorkerParameters params) {
        super(context, params);
    }

    @Override
    public ListenableWorker.Result doWork() {
        Log.d(TAG, "Starting work...");
        Context c = getApplicationContext();
        SharedPreferences sharedPref = c.getSharedPreferences(MainActivity.SHARED_PREF_SETTINGS, Context.MODE_PRIVATE);

        int warnDays = sharedPref.getInt("warn-days", Integer.parseInt(c.getString(R.string.default_warn_days)));
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            RestrictionsManager restrictionsMgr = (RestrictionsManager) c.getSystemService(Context.RESTRICTIONS_SERVICE);
            Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
            warnDays = appRestrictions.getInt("warn-days", warnDays);
        }

        String aliases = sharedPref.getString("monitor-aliases", "");
        if(warnDays > 0) {
            for(String alias : aliases.split("\n")) {
                if(alias.isEmpty()) continue;
                try {
                    X509Certificate[] chain = KeyChain.getCertificateChain(c, alias);
                    if(chain != null && chain.length > 0) {
                        long expiresInDays = TimeUnit.DAYS.convert(chain[0].getNotAfter().getTime() - (new Date()).getTime(), TimeUnit.MILLISECONDS);
                        String warnText = alias+" expires on "+chain[0].getNotAfter().toString();
                        if(expiresInDays < warnDays) {
                            Intent i = new Intent(c, MainActivity.class);
                            showNotification(c, "Certificate Expiration Warning", warnText, i, 0);
                            Log.w(TAG, warnText);
                        } else {
                            Log.i(TAG, warnText);
                        }
                    } else {
                        Log.w(TAG, "No cert found for alias: "+alias);
                    }
                } catch(KeyChainException | InterruptedException e) {
                    Log.e(TAG, e.getMessage());
                }
            }
        } else {
            Log.w(TAG, "warn-days is 0, cancelling check!");
        }

        // indicate whether the work finished successfully with the Result
        return Result.success();
    }

    public void showNotification(Context context, String title, String message, Intent intent, int reqCode) {
        PendingIntent pendingIntent = PendingIntent.getActivity(context, reqCode, intent, PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder notificationBuilder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.icon_24dp)
                .setContentTitle(title)
                .setContentText(message)
                .setAutoCancel(true)
                .setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION))
                .setContentIntent(pendingIntent);
        NotificationManager notificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            int importance = NotificationManager.IMPORTANCE_HIGH;
            NotificationChannel mChannel = new NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance);
            notificationManager.createNotificationChannel(mChannel);
        }
        notificationManager.notify(reqCode, notificationBuilder.build());
    }
}
