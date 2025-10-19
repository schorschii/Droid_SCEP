package systems.sieber.droid_scep;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;

public class CommonDialog {
    enum Icon {
        OK,
        ERROR,
        WARN
    }
    static void show(final Activity a, String title, String text, Icon icon, final boolean finishIntent) {
        AlertDialog ad = new AlertDialog.Builder(a).create();
        ad.setCancelable(false);
        if(title != null && !title.equals("")) ad.setTitle(title);
        if(icon != null && icon == Icon.OK) {
            if(text != null && (!text.equals(""))) ad.setMessage(text);
            ad.setIcon(a.getResources().getDrawable(R.drawable.ic_done_green_24dp));
        } else if(icon != null && icon == Icon.ERROR) {
            if(text != null && (!text.equals(""))) ad.setMessage(text);
            ad.setIcon(a.getResources().getDrawable(R.drawable.ic_error_red_24dp));
        } else if(icon != null && icon == Icon.WARN) {
            if(text != null && (!text.equals(""))) ad.setMessage(text);
            ad.setIcon(a.getResources().getDrawable(R.drawable.ic_warning_orange_24dp));
        } else {
            ad.setMessage(text);
        }
        ad.setButton(a.getResources().getString(R.string.ok), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                if(finishIntent) a.finish();
            }
        });
        ad.show();
    }
}
