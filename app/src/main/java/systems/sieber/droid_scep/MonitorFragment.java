package systems.sieber.droid_scep;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;


public class MonitorFragment extends Fragment {

    Activity activity;

    EditText editTextMonitorAliases;
    EditText editTextWarnDays;

    SharedPreferences sharedPref;

    interface KeySelectedCallback {
        void selected(String aliases);
    }

    public MonitorFragment() {
        // Required empty public constructor
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity = getActivity();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        View v = getView();
        if(v == null) return;

        // find views
        editTextMonitorAliases = v.findViewById(R.id.editTextMonitorAliases);
        editTextWarnDays = v.findViewById(R.id.editTextMonitorWarnDays);

        // load settings
        sharedPref = activity.getSharedPreferences(MainActivity.SHARED_PREF_SETTINGS, Context.MODE_PRIVATE);
        editTextMonitorAliases.setText( sharedPref.getString("monitor-aliases", "") );
        editTextWarnDays.setText( Integer.toString(sharedPref.getInt("warn-days", Integer.parseInt(getString(R.string.default_warn_days)))) );

        // register events
        SharedPreferences.Editor edit = sharedPref.edit();
        TextWatcher tw = new TextWatcher() {
            @Override
            public void afterTextChanged(Editable editable) {
                edit.putString("monitor-aliases", editTextMonitorAliases.getText().toString());
                edit.putInt("warn-days", Integer.parseInt(editTextWarnDays.getText().toString()));
                edit.apply();
            }
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }
            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }
        };
        editTextMonitorAliases.addTextChangedListener(tw);
        editTextWarnDays.addTextChangedListener(tw);
        v.findViewById(R.id.buttonAddCertAlias).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                askAddCertMonitoring(activity, editTextMonitorAliases.getText().toString(), null, new KeySelectedCallback() {
                    @Override
                    public void selected(String aliases) {
                        activity.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                editTextMonitorAliases.setText(aliases);
                            }
                        });
                    }
                });
            }
        });
        v.findViewById(R.id.buttonNotificationPermission).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                askNotificationPermission(activity);
            }
        });
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int permissionState = ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS);
            if(permissionState == PackageManager.PERMISSION_GRANTED) {
                v.findViewById(R.id.buttonNotificationPermission).setEnabled(false);
            }
        }

        // apply policies
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            RestrictionsManager restrictionsMgr = (RestrictionsManager) activity.getSystemService(Context.RESTRICTIONS_SERVICE);
            Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
            if(appRestrictions.containsKey("warn-days")) {
                editTextWarnDays.setText( Integer.toString(appRestrictions.getInt("warn-days", 0)) );
                editTextWarnDays.setEnabled(false);
            }
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_monitor, container, false);
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