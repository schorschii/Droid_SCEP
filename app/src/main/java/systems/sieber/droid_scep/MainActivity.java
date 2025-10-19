package systems.sieber.droid_scep;

import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.KeyChain;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

public class MainActivity extends AppCompatActivity {

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
		CharSequence sURI = editTextUrl.getText();
		int isKeyLen = Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem()));

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

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
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
			startActivity(intent);

		} catch(ScepClient.RequestPendingException e) {
			CommonDialog.show(this, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
			editTextTransactionId.setText(e.getTransactionId());

			SharedPreferences.Editor editor = sharedPref.edit();
			editor.putString("cert", e.getCertPem());
			editor.putString("key", e.getKeyPem());
			editor.putString("tid", e.getTransactionId());
			editor.apply();

		} catch(ScepClient.BadRequestException e) {
			CommonDialog.show(this, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();

		} catch(Exception e) {
			CommonDialog.show(this, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();
		}
	}

	public void onClickPoll(View view) {
		if(sharedPref.getString("cert", "").isEmpty()
		|| sharedPref.getString("key", "").isEmpty()
		|| sharedPref.getString("tid", "").isEmpty()) {
			CommonDialog.show(this, getString(R.string.no_request_pending), "", CommonDialog.Icon.WARN, false);
			return;
		}

		CharSequence sURI = editTextUrl.getText();

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

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

			// import into system/user keystore
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
			startActivity(intent);

			// clear temp data
			SharedPreferences.Editor editor = sharedPref.edit();
			editor.remove("cert");
			editor.remove("key");
			editor.remove("tid");
			editor.apply();
			editTextTransactionId.setText("");

		} catch(ScepClient.RequestPendingException e) {
			CommonDialog.show(this, e.getClass().getName(), getString(R.string.request_pending_help), CommonDialog.Icon.WARN, false);
			editTextTransactionId.setText(e.getTransactionId());

			SharedPreferences.Editor editor = sharedPref.edit();
			editor.putString("cert", e.getCertPem());
			editor.putString("key", e.getKeyPem());
			editor.putString("tid", e.getTransactionId());
			editor.apply();

		} catch(ScepClient.BadRequestException e) {
			CommonDialog.show(this, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();

		} catch(Exception e) {
			CommonDialog.show(this, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();
		}
	}

}
