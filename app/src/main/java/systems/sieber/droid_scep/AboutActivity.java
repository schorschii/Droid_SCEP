package systems.sieber.droid_scep;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

public class AboutActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);

        // init toolbar
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if(getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // get version
        try {
            PackageInfo pInfo = this.getPackageManager().getPackageInfo(getPackageName(), 0);
            ((TextView) findViewById(R.id.textViewVersion)).setText(
                    getResources().getString(R.string.version) + " " + pInfo.versionName
            );
        } catch(PackageManager.NameNotFoundException ignored) { }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch(item.getItemId()) {
            case android.R.id.home:
                finish();
                break;
        }
        return true;
    }

    public void onClickGithub(View v) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(getResources().getString(R.string.link_github)));
        startActivity(browserIntent);
    }

    public void onClickLicense(View v) {
        Intent licenseIntent = new Intent(this, LicenseActivity.class);
        startActivity(licenseIntent);
    }

    public void onClickGithubBase(View v) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(getResources().getString(R.string.link_github_base)));
        startActivity(browserIntent);
    }

    public void onClickGithubJscep(View v) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(getResources().getString(R.string.link_github_jscep)));
        startActivity(browserIntent);
    }

    public void onClickOco(View v) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(getResources().getString(R.string.link_github_oco)));
        startActivity(browserIntent);
    }

    public void onClickMasterplan(View v) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(getResources().getString(R.string.link_github_masterplan)));
        startActivity(browserIntent);
    }

}
