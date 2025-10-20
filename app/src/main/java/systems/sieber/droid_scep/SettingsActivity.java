package systems.sieber.droid_scep;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class SettingsActivity  extends AppCompatActivity {

    EditText editTextMonitorAliases;
    EditText editTextWarnDays;

    SharedPreferences sharedPref;

    interface KeySelectedCallback {
        void selected(String aliases);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        // init toolbar
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if(getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // find views
        editTextMonitorAliases = findViewById(R.id.editTextMonitorAliases);
        editTextWarnDays = findViewById(R.id.editTextMonitorWarnDays);

        // load settings
        sharedPref = getSharedPreferences(MainActivity.SHARED_PREF_SETTINGS, Context.MODE_PRIVATE);
        editTextMonitorAliases.setText( sharedPref.getString("monitor-aliases", "") );
        editTextWarnDays.setText( Integer.toString(sharedPref.getInt("warn-days", Integer.parseInt(getString(R.string.default_warn_days)))) );

        // apply policies
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            RestrictionsManager restrictionsMgr = (RestrictionsManager) getSystemService(Context.RESTRICTIONS_SERVICE);
            Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
            if(appRestrictions.containsKey("warn-days")) {
                editTextWarnDays.setText( Integer.toString(appRestrictions.getInt("warn-days", 0)) );
                editTextWarnDays.setEnabled(false);
            }
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_settings, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch(item.getItemId()) {
            case android.R.id.home:
                finish();
                break;
            case R.id.action_save:
                SharedPreferences.Editor edit = sharedPref.edit();
                edit.putString("monitor-aliases", editTextMonitorAliases.getText().toString());
                edit.putInt("warn-days", Integer.parseInt(editTextWarnDays.getText().toString()));
                edit.apply();
                finish();
                break;
        }
        return true;
    }

    public void onClickAddCertAlias(View v) {
         askAddCertMonitoring(this, editTextMonitorAliases.getText().toString(), null, new KeySelectedCallback() {
             @Override
             public void selected(String aliases) {
                 runOnUiThread(new Runnable() {
                     @Override
                     public void run() {
                         editTextMonitorAliases.setText(aliases);
                     }
                 });
             }
         });
    }

    public void onClickNotificationPermission(View v) {
        askNotificationPermission(this);
    }

    static void askAddCertMonitoring(Activity a, String aliases, String fallbackAlias, KeySelectedCallback callback) {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            callback.selected( addToStringIfNotExist(aliases, fallbackAlias) );
            askNotificationPermission(a);
            return;
        }
        KeyChain.choosePrivateKeyAlias(a, new KeyChainAliasCallback() {
            @Override
            public void alias(@Nullable String s) {
                if(s == null) return;
                callback.selected( addToStringIfNotExist(aliases, s) );
                askNotificationPermission(a);
            }
        }, new String[]{}, null, null, null);
    }

    static String addToStringIfNotExist(String list, String add) {
        boolean found = false;
        for(String a : list.split("\n")) {
            if(a.equals(add)) {
                found = true;
                break;
            }
        }
        if(!found) {
            return (list+"\n"+add).replaceAll("\n$", "").replaceAll("^\n", "");
        } else {
            return list;
        }
    }

    static void askNotificationPermission(Activity a) {
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int permissionState = ContextCompat.checkSelfPermission(a, Manifest.permission.POST_NOTIFICATIONS);
            if(permissionState == PackageManager.PERMISSION_DENIED) {
                ActivityCompat.requestPermissions(a, new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 1);
            }
        }
    }

}
