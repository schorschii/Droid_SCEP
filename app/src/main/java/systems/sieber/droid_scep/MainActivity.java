package systems.sieber.droid_scep;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.fragment.app.Fragment;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;

import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.util.concurrent.TimeUnit;

public class MainActivity extends AppCompatActivity {

	static String SHARED_PREF_TEMP_STORE = "temp-store";
	static String SHARED_PREF_SETTINGS = "settings";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		// init toolbar
		Toolbar toolbar = findViewById(R.id.toolbar);
		setSupportActionBar(toolbar);

		// init bottom navigation
		BottomNavigationView bottomNavigationView = findViewById(R.id.bottom_navigation);
		setCurrentFragment(new ScepFragment());
		bottomNavigationView.setOnItemSelectedListener(menuItem -> {
			switch(menuItem.getItemId()) {
				case R.id.action_scep:
					setCurrentFragment(new ScepFragment());
					break;
				case R.id.action_monitor:
					setCurrentFragment(new MonitorFragment());
					break;
				case R.id.action_extras:
					setCurrentFragment(new ExtrasFragment());
					break;
			}
			// Return true to indicate that we handled the item click
			return true;
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
			case R.id.action_about:
				startActivity(new Intent(this, AboutActivity.class));
				break;
		}
		return true;
	}

	private void setCurrentFragment(Fragment fragment) {
		getSupportFragmentManager()
				.beginTransaction()
				// Replace the fragment inside the container with the new fragment
				.replace(R.id.fragment_container, fragment)
				// Commit the transaction to actually perform the change
				.commit();
	}

}
