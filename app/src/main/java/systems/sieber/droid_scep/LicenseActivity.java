package systems.sieber.droid_scep;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.MenuItem;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import java.io.InputStream;

public class LicenseActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_license);

        // init toolbar
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if(getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // load text
        try {
            Resources res = getResources();
            InputStream in_s = res.openRawResource(R.raw.mit_license);
            byte[] b = new byte[in_s.available()];
            in_s.read(b);
            ((TextView) findViewById(R.id.textViewLicense)).setText(new String(b));
        } catch(Exception e) {
            e.printStackTrace();
            ((TextView) findViewById(R.id.textViewLicense)).setText("???");
        }
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

}
