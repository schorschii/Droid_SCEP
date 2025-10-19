package systems.sieber.droid_scep;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.KeyChain;
import android.view.Menu;
import android.view.View;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.TextView;

public class MainActivity extends Activity {

	TextView editTextUrl;
	TextView editTextCommonName;
	TextView editTextEnrollmentChallenge;
	TextView editTextKeystorePassword;
	Spinner spinnerKeyLen;
	String keystoreAlias;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		editTextUrl = findViewById(R.id.editTextScepUrl);
		editTextCommonName = findViewById(R.id.exitTextCommonName);
		editTextEnrollmentChallenge = findViewById(R.id.editTextEnrollmentChallenge);
		editTextKeystorePassword = findViewById(R.id.editTextKeystorePassword);
		spinnerKeyLen = findViewById(R.id.spinnerKeySize);

		applyPolicies();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	private void applyPolicies() {
		if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
			RestrictionsManager restrictionsMgr = (RestrictionsManager) getSystemService(Context.RESTRICTIONS_SERVICE);
			Bundle appRestrictions = restrictionsMgr.getApplicationRestrictions();
			editTextUrl.setText( appRestrictions.getString("scep-url", getString(R.string.default_server_url)) );
			editTextCommonName.setText( appRestrictions.getString("subject-dn", getString(R.string.default_subject_dn)) );
			editTextEnrollmentChallenge.setText( appRestrictions.getString("enrollment-challenge", "1FDE8ED526747EADB0681A952963CDE4") );
			editTextKeystorePassword.setText( appRestrictions.getString("keystore-password", "") );
			keystoreAlias = appRestrictions.getString("keystore-alias", getString(R.string.default_keystore_alias));

			String defaultRsaKeyLen = String.valueOf( appRestrictions.getInt("rsa-key-length", Integer.parseInt(getString(R.string.default_rsa_len))) );
			SpinnerAdapter adapter = spinnerKeyLen.getAdapter();
			for(int i = 0; i < adapter.getCount(); i++) {
				if(adapter.getItem(i).toString().equals(defaultRsaKeyLen)) {
					spinnerKeyLen.setSelection(i);
				}
			}
		}
	}

	public void onClickEnroll(View view) {
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
					isKeyLen,
					keystoreAlias,
					editTextKeystorePassword.getText().toString()
			);

			// import into system/user keystore
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
			startActivity(intent);

		} catch(ScepClient.BadRequestException e) {
			CommonDialog.show(this, e.getClass().getName(), getString(R.string.bad_request_help), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();
		} catch(Exception e) {
			CommonDialog.show(this, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();
		}
	}
}
