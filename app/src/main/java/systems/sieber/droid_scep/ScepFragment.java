package systems.sieber.droid_scep;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import android.os.StrictMode;
import android.security.KeyChain;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;

import java.io.OutputStream;


public class ScepFragment extends Fragment {

    Activity activity;

    Button buttonRequest;
    Button buttonPoll;
    EditText editTextUrl;
    RadioButton radioButtonImportToAndroidKeystore;
    RadioButton radioButtonSaveToFile;
    EditText editTextCaFingerprint;
    EditText editTextCommonName;
    EditText editTextEnrollmentChallenge;
    EditText editTextEnrollmentProfile;
    EditText editTextKeystorePassword;
    EditText editTextTransactionId;
    Spinner spinnerKeyLen;
    String keystoreAlias;

    SharedPreferences sharedPrefTemp;
    SharedPreferences sharedPrefSettings;

    ActivityResultLauncher<Intent> arlInstallCertificate;
    ActivityResultLauncher<Intent> arlSaveCertificate;
    String tempAlias;
    byte[] tempBytes;

    public ScepFragment() {
        // Required empty public constructor
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        View v = getView();
        if(v == null) return;

        // find views
        buttonRequest = v.findViewById(R.id.buttonRequest);
        buttonPoll = v.findViewById(R.id.buttonPoll);
        editTextUrl = v.findViewById(R.id.editTextScepUrl);
        radioButtonImportToAndroidKeystore = v.findViewById(R.id.radioButtonImportToAndroidKeystore);
        radioButtonSaveToFile = v.findViewById(R.id.radioButtonSaveToFile);
        editTextCaFingerprint = v.findViewById(R.id.exitTextCaFingerprint);
        editTextCommonName = v.findViewById(R.id.exitTextCommonName);
        editTextEnrollmentChallenge = v.findViewById(R.id.editTextEnrollmentChallenge);
        editTextEnrollmentProfile = v.findViewById(R.id.editTextEnrollmentProfile);
        editTextKeystorePassword = v.findViewById(R.id.editTextKeystorePassword);
        editTextTransactionId = v.findViewById(R.id.exitTextTransactionId);
        spinnerKeyLen = v.findViewById(R.id.spinnerKeySize);

        // load settings
        if(activity != null) {
            sharedPrefTemp = activity.getSharedPreferences(MainActivity.SHARED_PREF_TEMP_STORE, Context.MODE_PRIVATE);
            sharedPrefSettings = activity.getSharedPreferences(MainActivity.SHARED_PREF_SETTINGS, Context.MODE_PRIVATE);
            editTextUrl.setText( sharedPrefSettings.getString("scep-url", getString(R.string.default_server_url)) );
            if(sharedPrefSettings.getBoolean("save-to-file", false)) {
                radioButtonSaveToFile.setChecked(true);
            } else {
                radioButtonImportToAndroidKeystore.setChecked(true);
            }
            editTextCaFingerprint.setText( sharedPrefSettings.getString("ca-fingerprint", "") );
            editTextCommonName.setText( sharedPrefSettings.getString("subject-dn", getString(R.string.default_subject_dn)) );
            editTextEnrollmentChallenge.setText( sharedPrefSettings.getString("enrollment-challenge", getString(R.string.default_enrollment_challenge)) );
            editTextEnrollmentProfile.setText( sharedPrefSettings.getString("enrollment-profile", getString(R.string.default_enrollment_profile)) );
            setSpinnerDefault(spinnerKeyLen, String.valueOf(sharedPrefSettings.getInt("rsa-key-length", Integer.parseInt(getString(R.string.default_rsa_len)))));
            editTextTransactionId.setText( sharedPrefTemp.getString("tid", "") );
            keystoreAlias = getString(R.string.default_keystore_alias);

            // apply MDM policies
            applyPolicies();
        }

        // init buttons
        buttonRequest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(sharedPrefTemp.getString("cert", "").isEmpty()
                        || sharedPrefTemp.getString("key", "").isEmpty()
                        || sharedPrefTemp.getString("tid", "").isEmpty()) {
                    request();
                } else {
                    AlertDialog.Builder ad = new AlertDialog.Builder(activity);
                    ad.setCancelable(false);
                    ad.setIcon(getResources().getDrawable(R.drawable.ic_warning_orange_24dp));
                    ad.setTitle(getString(R.string.request_already_sent));
                    ad.setMessage(getString(R.string.overwrite_pending_request));
                    ad.setPositiveButton(getResources().getString(R.string.yes), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            request();
                        }
                    });
                    ad.setNegativeButton(getResources().getString(R.string.no), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    ad.show();
                }
            }
        });
        buttonPoll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(sharedPrefTemp.getString("cert", "").isEmpty()
                        || sharedPrefTemp.getString("key", "").isEmpty()
                        || sharedPrefTemp.getString("tid", "").isEmpty()) {
                    CommonDialog.show(activity, getString(R.string.no_request_pending), "", CommonDialog.Icon.WARN, false);
                    return;
                }
                poll();
            }
        });
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity = getActivity();

        // init result launcher
        arlInstallCertificate = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        AlertDialog.Builder ad = new AlertDialog.Builder(activity);
                        ad.setMessage(getString(R.string.add_to_monitoring));
                        ad.setPositiveButton(getResources().getString(R.string.yes), new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                                // add cert to monitoring
                                String oldAliases = sharedPrefSettings.getString("monitor-aliases", "");
                                MonitorFragment.askAddCertMonitoring(activity, oldAliases, tempAlias, new MonitorFragment.KeySelectedCallback() {
                                    @Override
                                    public void selected(String aliases) {
                                        SharedPreferences.Editor edit = sharedPrefSettings.edit();
                                        edit.putString("monitor-aliases", aliases);
                                        edit.apply();
                                    }
                                });
                            }
                        });
                        ad.setNegativeButton(getResources().getString(R.string.no), new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });
                        ad.show();
                    }
                });
        arlSaveCertificate = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            OutputStream output = activity.getContentResolver().openOutputStream(uri);
                            output.write(tempBytes);
                            output.flush();
                            output.close();
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_scep, container, false);
    }

    @Override
    public void onPause() {
        super.onPause();

        // save settings
        SharedPreferences.Editor edit = sharedPrefSettings.edit();
        edit.putString("scep-url", editTextUrl.getText().toString());
        edit.putBoolean("save-to-file", radioButtonSaveToFile.isChecked());
        edit.putString("subject-dn", editTextCommonName.getText().toString());
        edit.putString("enrollment-challenge", editTextEnrollmentChallenge.getText().toString());
        edit.putString("enrollment-profile", editTextEnrollmentProfile.getText().toString());
        edit.putInt("rsa-key-length", Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem())));
        edit.apply();
    }

    private void applyPolicies() {
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            RestrictionsManager restrictionsMgr = (RestrictionsManager) activity.getSystemService(Context.RESTRICTIONS_SERVICE);
            Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();

            String url = appRestrictions.getString("scep-url", null);
            if(url != null) {
                editTextUrl.setText(url);
                editTextUrl.setEnabled(false);
            }

            if(appRestrictions.containsKey("save-to-file")) {
                if(appRestrictions.getBoolean("save-to-file", false)) {
                    radioButtonSaveToFile.setChecked(true);
                } else {
                    radioButtonImportToAndroidKeystore.setChecked(true);
                }
                radioButtonSaveToFile.setEnabled(false);
                radioButtonImportToAndroidKeystore.setEnabled(false);
            }

            String caFingerprint = appRestrictions.getString("ca-fingerprint", null);
            if(caFingerprint != null) {
                editTextCaFingerprint.setText(caFingerprint);
                editTextCaFingerprint.setEnabled(false);
            }

            String subjectDn = appRestrictions.getString("subject-dn", null);
            if(subjectDn != null) {
                editTextCommonName.setText(subjectDn);
                editTextCommonName.setEnabled(false);
            }

            String enrollmentChallenge = appRestrictions.getString("enrollment-challenge", null);
            if(enrollmentChallenge != null) {
                editTextEnrollmentChallenge.setText(enrollmentChallenge);
                editTextEnrollmentChallenge.setEnabled(false);
            }

            String enrollmentProfile = appRestrictions.getString("enrollment-profile", null);
            if(enrollmentProfile != null) {
                editTextEnrollmentProfile.setText(enrollmentProfile);
                editTextEnrollmentProfile.setEnabled(false);
            }

            String keystorePassword = appRestrictions.getString("keystore-password", null);
            if(keystorePassword != null) {
                editTextKeystorePassword.setText(keystorePassword);
                editTextKeystorePassword.setEnabled(false);
            }

            keystoreAlias = appRestrictions.getString("keystore-alias", keystoreAlias);

            int defaultRsaKeyLenInt = appRestrictions.getInt("rsa-key-length", 0);
            if(defaultRsaKeyLenInt > 0) {
                setSpinnerDefault(spinnerKeyLen, String.valueOf(defaultRsaKeyLenInt));
                spinnerKeyLen.setEnabled(false);
            }
        }
    }

    private void setSpinnerDefault(Spinner s, String def) {
        SpinnerAdapter adapter = s.getAdapter();
        for(int i = 0; i < adapter.getCount(); i++) {
            if(adapter.getItem(i).toString().equals(def)) {
                s.setSelection(i);
            }
        }
    }

    private void request() {
        buttonRequest.setEnabled(false);
        buttonRequest.setText(getString(R.string.please_wait));

        CharSequence sURI = editTextUrl.getText();
        int isKeyLen = Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem()));

        // enable some policies
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] keystore = ScepClient.CertReq(
                            sURI.toString(),
                            editTextCommonName.getText().toString(),
                            editTextEnrollmentChallenge.getText().toString(),
                            editTextCaFingerprint.getText().toString().replace(" ", "").trim(),
                            editTextEnrollmentProfile.getText().toString(),
                            isKeyLen,
                            keystoreAlias,
                            editTextKeystorePassword.getText().toString()
                    );

                    // import into system/user keystore
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            installCert(keystore, keystoreAlias);
                        }
                    });

                } catch(ScepClient.RequestPendingException e) {
                    SharedPreferences.Editor editor = sharedPrefTemp.edit();
                    editor.putString("cert", e.getCertPem());
                    editor.putString("key", e.getKeyPem());
                    editor.putString("tid", e.getTransactionId());
                    editor.apply();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
                            editTextTransactionId.setText(e.getTransactionId());
                        }
                    });

                } catch(ScepClient.BadRequestException e) {
                    e.printStackTrace();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
                        }
                    });

                } catch(Exception e) {
                    e.printStackTrace();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
                        }
                    });

                } finally {
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            buttonRequest.setEnabled(true);
                            buttonRequest.setText(getString(R.string.request));
                        }
                    });
                }
            }
        });
    }

    private void poll() {
        buttonPoll.setEnabled(false);
        buttonPoll.setText(getString(R.string.please_wait));

        CharSequence sURI = editTextUrl.getText();

        // enable some policies
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] keystore = ScepClient.CertPoll(
                            sURI.toString(),
                            sharedPrefTemp.getString("cert", ""),
                            sharedPrefTemp.getString("key", ""),
                            editTextCommonName.getText().toString(),
                            sharedPrefTemp.getString("tid", ""),
                            keystoreAlias,
                            editTextKeystorePassword.getText().toString()
                    );

                    // clear temp data
                    SharedPreferences.Editor editor = sharedPrefTemp.edit();
                    editor.remove("cert");
                    editor.remove("key");
                    editor.remove("tid");
                    editor.apply();

                    // import into system/user keystore
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            installCert(keystore, keystoreAlias);

                            // clear temp data
                            editTextTransactionId.setText("");
                        }
                    });

                } catch(ScepClient.RequestPendingException e) {
                    SharedPreferences.Editor editor = sharedPrefTemp.edit();
                    editor.putString("cert", e.getCertPem());
                    editor.putString("key", e.getKeyPem());
                    editor.putString("tid", e.getTransactionId());
                    editor.apply();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
                            editTextTransactionId.setText(e.getTransactionId());
                        }
                    });

                } catch(ScepClient.BadRequestException e) {
                    e.printStackTrace();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
                        }
                    });

                } catch(Exception e) {
                    e.printStackTrace();
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            CommonDialog.show(activity, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
                        }
                    });

                } finally {
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            buttonPoll.setEnabled(true);
                            buttonPoll.setText(getString(R.string.poll));
                        }
                    });
                }
            }
        });
    }

    private void installCert(byte[] keystore, String alias) {
        if(radioButtonSaveToFile.isChecked()) {
            tempBytes = keystore;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/x-pkcs12");
            intent.putExtra(Intent.EXTRA_TITLE, alias+".p12");
            arlSaveCertificate.launch(intent);
        } else {
            tempAlias = alias;
            Intent intent = KeyChain.createInstallIntent();
            intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
            arlInstallCertificate.launch(intent);
        }
    }

}
