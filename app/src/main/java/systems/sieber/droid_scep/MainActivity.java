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
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

public class MainActivity extends AppCompatActivity {

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

	SharedPreferences sharedPref;

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
		sharedPref = getSharedPreferences("temp-store", Context.MODE_PRIVATE);
		editTextTransactionId.setText( sharedPref.getString("tid", "") );
		keystoreAlias = getString(R.string.default_keystore_alias);

		// apply MDM policies
		applyPolicies();
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
			case R.id.action_about:
				Intent i = new Intent(this, AboutActivity.class);
				startActivity(i);
				break;
		}
		return true;
	}

	private void applyPolicies() {
		if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
			RestrictionsManager restrictionsMgr = (RestrictionsManager) getSystemService(Context.RESTRICTIONS_SERVICE);
			Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
			editTextUrl.setText( appRestrictions.getString("scep-url", getString(R.string.default_server_url)) );
			editTextCommonName.setText( appRestrictions.getString("subject-dn", getString(R.string.default_subject_dn)) );
			editTextEnrollmentChallenge.setText( appRestrictions.getString("enrollment-challenge", "1FDE8ED526747EADB0681A952963CDE4") );
			editTextEnrollmentProfile.setText( appRestrictions.getString("enrollment-profile", getString(R.string.default_enrollment_profile)) );
			editTextKeystorePassword.setText( appRestrictions.getString("keystore-password", "") );
			keystoreAlias = appRestrictions.getString("keystore-alias", keystoreAlias);

			String defaultRsaKeyLen = String.valueOf( appRestrictions.getInt("rsa-key-length", Integer.parseInt(getString(R.string.default_rsa_len))) );
			SpinnerAdapter adapter = spinnerKeyLen.getAdapter();
			for(int i = 0; i < adapter.getCount(); i++) {
				if(adapter.getItem(i).toString().equals(defaultRsaKeyLen)) {
					spinnerKeyLen.setSelection(i);
				}
			}
		}
	}

	public void onClickRequest(View view) {
		if(sharedPref.getString("cert", "").isEmpty()
				|| sharedPref.getString("key", "").isEmpty()
				|| sharedPref.getString("tid", "").isEmpty()) {
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
							Intent intent = KeyChain.createInstallIntent();
							intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
							startActivity(intent);
						}
					});

				} catch(ScepClient.RequestPendingException e) {
					SharedPreferences.Editor editor = sharedPref.edit();
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
		if(sharedPref.getString("cert", "").isEmpty()
		|| sharedPref.getString("key", "").isEmpty()
		|| sharedPref.getString("tid", "").isEmpty()) {
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
							sharedPref.getString("cert", ""),
							sharedPref.getString("key", ""),
							editTextCommonName.getText().toString(),
							sharedPref.getString("tid", ""),
							keystoreAlias,
							editTextKeystorePassword.getText().toString()
					);

					// clear temp data
					SharedPreferences.Editor editor = sharedPref.edit();
					editor.remove("cert");
					editor.remove("key");
					editor.remove("tid");
					editor.apply();

					// import into system/user keystore
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							Intent intent = KeyChain.createInstallIntent();
							intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
							startActivity(intent);

							// clear temp data
							editTextTransactionId.setText("");
						}
					});

				} catch(ScepClient.RequestPendingException e) {
					SharedPreferences.Editor editor = sharedPref.edit();
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

}
