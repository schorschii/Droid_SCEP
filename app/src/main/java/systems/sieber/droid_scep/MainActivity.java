package systems.sieber.droid_scep;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.KeyChain;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;

import java.util.concurrent.TimeUnit;

public class MainActivity extends AppCompatActivity {

	static String SHARED_PREF_TEMP_STORE = "temp-store";
	static String SHARED_PREF_SETTINGS = "settings";

	Button buttonRequest;
	Button buttonPoll;
	EditText editTextUrl;
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
	String tempAlias;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		// init toolbar
		Toolbar toolbar = findViewById(R.id.toolbar);
		setSupportActionBar(toolbar);

		// find views
		buttonRequest = findViewById(R.id.buttonRequest);
		buttonPoll = findViewById(R.id.buttonPoll);
		editTextUrl = findViewById(R.id.editTextScepUrl);
		editTextCommonName = findViewById(R.id.exitTextCommonName);
		editTextEnrollmentChallenge = findViewById(R.id.editTextEnrollmentChallenge);
		editTextEnrollmentProfile = findViewById(R.id.editTextEnrollmentProfile);
		editTextKeystorePassword = findViewById(R.id.editTextKeystorePassword);
		editTextTransactionId = findViewById(R.id.exitTextTransactionId);
		spinnerKeyLen = findViewById(R.id.spinnerKeySize);

		// load settings
		sharedPrefTemp = getSharedPreferences(SHARED_PREF_TEMP_STORE, Context.MODE_PRIVATE);
		sharedPrefSettings = getSharedPreferences(SHARED_PREF_SETTINGS, Context.MODE_PRIVATE);
		editTextUrl.setText( sharedPrefSettings.getString("scep-url", getString(R.string.default_server_url)) );
		editTextCommonName.setText( sharedPrefSettings.getString("subject-dn", getString(R.string.default_subject_dn)) );
		editTextEnrollmentChallenge.setText( sharedPrefSettings.getString("enrollment-challenge", getString(R.string.default_enrollment_challenge)) );
		editTextEnrollmentProfile.setText( sharedPrefSettings.getString("enrollment-profile", getString(R.string.default_enrollment_profile)) );
		setSpinnerDefault(spinnerKeyLen, String.valueOf(sharedPrefSettings.getInt("rsa-key-length", Integer.parseInt(getString(R.string.default_rsa_len)))));
		editTextTransactionId.setText( sharedPrefTemp.getString("tid", "") );
		keystoreAlias = getString(R.string.default_keystore_alias);

		// apply MDM policies
		applyPolicies();

		// init result launcher
		AppCompatActivity me = this;
		arlInstallCertificate = registerForActivityResult(
				new ActivityResultContracts.StartActivityForResult(),
				new ActivityResultCallback<ActivityResult>() {
					@Override
					public void onActivityResult(ActivityResult result) {
						if(result.getResultCode() != Activity.RESULT_OK) return;
						AlertDialog.Builder ad = new AlertDialog.Builder(me);
						ad.setMessage(getString(R.string.add_to_monitoring));
						ad.setPositiveButton(getResources().getString(R.string.yes), new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int which) {
								dialog.dismiss();
								// add cert to monitoring
								String oldAliases = sharedPrefSettings.getString("monitor-aliases", "");
								SettingsActivity.askAddCertMonitoring(me, oldAliases, tempAlias, new SettingsActivity.KeySelectedCallback() {
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

		// init cert check background worker
		PeriodicWorkRequest saveRequest =
				new PeriodicWorkRequest.Builder(CertWatcher.class, 1, TimeUnit.DAYS)
						.build();
		WorkManager wm = WorkManager.getInstance(this);
		wm.enqueueUniquePeriodicWork("certCheck", ExistingPeriodicWorkPolicy.REPLACE, saveRequest);

        try {
            for(WorkInfo wi : wm.getWorkInfosByTag(CertWatcher.class.getName()).get()) {
                Log.i("WORK", wi.toString());
            }
        } catch(Exception ignored) { }

    }

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch(item.getItemId()) {
			case android.R.id.home:
				finish();
				break;
			case R.id.action_settings:
				startActivity(new Intent(this, SettingsActivity.class));
				break;
			case R.id.action_about:
				startActivity(new Intent(this, AboutActivity.class));
				break;
		}
		return true;
	}

	@Override
	protected void onPause() {
		super.onPause();

		// save settings
		SharedPreferences.Editor edit = sharedPrefSettings.edit();
		edit.putString("scep-url", editTextUrl.getText().toString());
		edit.putString("subject-dn", editTextCommonName.getText().toString());
		edit.putString("enrollment-challenge", editTextEnrollmentChallenge.getText().toString());
		edit.putString("enrollment-profile", editTextEnrollmentProfile.getText().toString());
		edit.putInt("rsa-key-length", Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem())));
		edit.apply();
	}

	private void applyPolicies() {
		if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
			RestrictionsManager restrictionsMgr = (RestrictionsManager) getSystemService(Context.RESTRICTIONS_SERVICE);
			Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();

			String url = appRestrictions.getString("scep-url", null);
			if(url != null) {
				editTextUrl.setText(url);
				editTextUrl.setEnabled(false);
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
		SpinnerAdapter adapter = spinnerKeyLen.getAdapter();
		for(int i = 0; i < adapter.getCount(); i++) {
			if(adapter.getItem(i).toString().equals(def)) {
				spinnerKeyLen.setSelection(i);
			}
		}
	}

	public void onClickRequest(View view) {
		if(sharedPrefTemp.getString("cert", "").isEmpty()
		|| sharedPrefTemp.getString("key", "").isEmpty()
		|| sharedPrefTemp.getString("tid", "").isEmpty()) {
			request();
		} else {
			AlertDialog.Builder ad = new AlertDialog.Builder(this);
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

	private void request() {
		buttonRequest.setEnabled(false);
		buttonRequest.setText(getString(R.string.please_wait));

		CharSequence sURI = editTextUrl.getText();
		int isKeyLen = Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem()));

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

		Activity a = this;
		AsyncTask.execute(new Runnable() {
			@Override
			public void run() {
				try {
					byte[] keystore = ScepClient.CertReq(
							sURI.toString(),
							editTextCommonName.getText().toString(),
							editTextEnrollmentChallenge.getText().toString(),
							editTextEnrollmentProfile.getText().toString(),
							isKeyLen,
							keystoreAlias,
							editTextKeystorePassword.getText().toString()
					);

					// import into system/user keystore
					runOnUiThread(new Runnable() {
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
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
							editTextTransactionId.setText(e.getTransactionId());
						}
					});

				} catch(ScepClient.BadRequestException e) {
					e.printStackTrace();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
						}
					});

				} catch(Exception e) {
					e.printStackTrace();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
						}
					});

				} finally {
					runOnUiThread(new Runnable() {
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

	public void onClickPoll(View view) {
		if(sharedPrefTemp.getString("cert", "").isEmpty()
		|| sharedPrefTemp.getString("key", "").isEmpty()
		|| sharedPrefTemp.getString("tid", "").isEmpty()) {
			CommonDialog.show(this, getString(R.string.no_request_pending), "", CommonDialog.Icon.WARN, false);
			return;
		}

		buttonPoll.setEnabled(false);
		buttonPoll.setText(getString(R.string.please_wait));

		CharSequence sURI = editTextUrl.getText();

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

		Activity a = this;
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
					runOnUiThread(new Runnable() {
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
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
							editTextTransactionId.setText(e.getTransactionId());
						}
					});

				} catch(ScepClient.BadRequestException e) {
					e.printStackTrace();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
						}
					});

				} catch(Exception e) {
					e.printStackTrace();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							CommonDialog.show(a, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
						}
					});

				} finally {
					runOnUiThread(new Runnable() {
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
		tempAlias = alias;
		Intent intent = KeyChain.createInstallIntent();
		intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
		arlInstallCertificate.launch(intent);
	}

}
