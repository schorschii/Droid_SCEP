package com.gordon.scep.client;

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.security.KeyChain;
import android.view.Menu;
import android.view.View;
import android.widget.Spinner;
import android.widget.TextView;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	public void onClickEnroll(View view) {
		TextView editTextUrl = findViewById(R.id.editTextScepUrl);
		CharSequence sURI = editTextUrl.getText();
		sURI.toString();

		Spinner spinnerKeyLen = findViewById(R.id.spinnerKeySize);
		int isKeyLen = Integer.parseInt(String.valueOf(spinnerKeyLen.getSelectedItem()));

		TextView textViewCommonName = findViewById(R.id.exitTextCommonName);
		TextView textViewPassword = findViewById(R.id.editTextPassword);

		// enable some policies
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
		StrictMode.setThreadPolicy(policy);

		try {
			byte[] keystore = ScepClient.CertReq(sURI.toString(), textViewCommonName.getText().toString(), textViewPassword.getText().toString(), isKeyLen);
			
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_PKCS12, keystore);
			startActivity(intent);

		} catch(Exception e) {
			CommonDialog.show(this, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
			e.printStackTrace();
		}
	}
}
