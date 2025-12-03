package systems.sieber.droid_scep;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;


public class ExtrasFragment extends Fragment {

    Activity activity;

    PrivateKey key;
    X509Certificate cert;
    byte[] p12;

    OutputStream csrKeyOut;
    OutputStream csrOut;

    public ExtrasFragment() {
        // Required empty public constructor
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity = getActivity();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        View v = getView();
        if(v == null) return;

        ActivityResultLauncher<Intent> arlWriteKey = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            csrKeyOut = activity.getContentResolver().openOutputStream(uri);

                            File file = new File(uri.toString());
                            ((EditText) v.findViewById(R.id.editTextCsrKeyFile)).setText(getFileDisplayName(file, uri));

                            if(csrKeyOut != null && csrOut != null) {
                                v.findViewById(R.id.buttonGenerateCsr).setEnabled(true);
                            }
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
        ActivityResultLauncher<Intent> arlWriteCsr = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            csrOut = activity.getContentResolver().openOutputStream(uri);

                            File file = new File(uri.toString());
                            ((EditText) v.findViewById(R.id.editTextCsrFile)).setText(getFileDisplayName(file, uri));

                            if(csrKeyOut != null && csrOut != null) {
                                v.findViewById(R.id.buttonGenerateCsr).setEnabled(true);
                            }
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
        ActivityResultLauncher<Intent> arlCert = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            InputStream input = activity.getContentResolver().openInputStream(uri);
                            String certPem = IOUtils.toString(new BufferedReader(new InputStreamReader(input)));
                            cert = ScepClient.pem2cert(certPem);
                            Log.i("PEM2PKCS12", cert.toString());
                            input.close();

                            File file = new File(uri.toString());
                            ((EditText) v.findViewById(R.id.editTextPemCertFile)).setText(getFileDisplayName(file, uri));

                            if(cert != null && key != null) {
                                v.findViewById(R.id.buttonPkcs12File).setEnabled(true);
                            }
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
        ActivityResultLauncher<Intent> arlKey = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            InputStream input = activity.getContentResolver().openInputStream(uri);
                            String keyPem = IOUtils.toString(new BufferedReader(new InputStreamReader(input)));
                            //Log.i("PEM2PKCS12", keyPem);
                            key = ScepClient.pem2key(keyPem);
                            input.close();

                            File file = new File(uri.toString());
                            ((EditText) v.findViewById(R.id.editTextPemKeyFile)).setText(getFileDisplayName(file, uri));

                            if(cert != null && key != null) {
                                v.findViewById(R.id.buttonPkcs12File).setEnabled(true);
                            }
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
        ActivityResultLauncher<Intent> arlWriteP12 = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if(result.getResultCode() != Activity.RESULT_OK) return;
                        try {
                            Uri uri = result.getData().getData();
                            OutputStream output = activity.getContentResolver().openOutputStream(uri);
                            output.write(p12);
                            output.flush();
                            output.close();
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                });

        // register events
        v.findViewById(R.id.buttonCsrKeyFile).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/x-pem-file");
                intent.putExtra(Intent.EXTRA_TITLE, "csr.key.pem");
                arlWriteKey.launch(intent);
            }
        });
        v.findViewById(R.id.buttonCsrFile).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/pkcs10");
                intent.putExtra(Intent.EXTRA_TITLE, "csr.pem");
                arlWriteCsr.launch(intent);
            }
        });
        v.findViewById(R.id.buttonGenerateCsr).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(4096);
                    KeyPair keyPair = keyGen.genKeyPair();
                    key = keyPair.getPrivate();

                    String cn = ((EditText) v.findViewById(R.id.editTextCommonNameCsr)).getText().toString();
                    X500Name entity = new X500Name(cn);

                    JcaContentSignerBuilder csb = new JcaContentSignerBuilder("SHA256withRSA");
                    ContentSigner cs = csb.build(keyPair.getPrivate());

                    ArrayList<GeneralName> names = new ArrayList<>();

                    // add email SAN
                    String email = ((EditText) v.findViewById(R.id.editTextEmail)).getText().toString();
                    if(!email.isEmpty()) {
                        names.add(new GeneralName(GeneralName.rfc822Name, email));
                    }

                    // add UPN SAN
                    String upn = ((EditText) v.findViewById(R.id.editTextUpn)).getText().toString();
                    if(!upn.isEmpty()) {
                        /*new GeneralName(GeneralName.otherName,
                                        new DERSequence(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                                                new DERTaggedObject(0, new DERUTF8String(upn))))*/
                        ASN1EncodableVector otherNameStruct = new ASN1EncodableVector();
                        otherNameStruct.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"));
                        otherNameStruct.add(new DERTaggedObject(0, new DERUTF8String(upn)));
                        names.add(new GeneralName(GeneralName.otherName, new DERSequence(otherNameStruct)));
                    }

                    // generate the CSR
                    PKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(
                            entity, keyPair.getPublic());
                    if(!names.isEmpty()) {
                        ExtensionsGenerator extGen = new ExtensionsGenerator();
                        GeneralNames subjectAltNames = new GeneralNames(names.toArray(new GeneralName[0]));
                        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
                        crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
                    }
                    String strCsr = ScepClient.csr2pem(crb.build(cs), true);

                    // save files
                    csrKeyOut.write(ScepClient.key2pem(key, true).getBytes());
                    csrKeyOut.flush();
                    csrKeyOut.close();

                    csrOut.write(strCsr.getBytes());
                    csrOut.flush();
                    csrOut.close();

                    AlertDialog.Builder ad = new AlertDialog.Builder(activity);
                    ad.setTitle(getString(R.string.csr_generated));
                    ad.setPositiveButton(getString(R.string.done), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    ad.setNeutralButton(getString(R.string.copy_to_clipboard), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            ClipboardManager clipboard = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                            ClipData clip = ClipData.newPlainText("CSR", strCsr);
                            clipboard.setPrimaryClip(clip);
                            dialog.dismiss();
                        }
                    });
                    ad.show();
                } catch(Exception e) {
                    CommonDialog.show(activity, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
                }
            }
        });
        v.findViewById(R.id.buttonGenerateCsr).setEnabled(false);

        v.findViewById(R.id.buttonPemCertFile).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/x-pem-file");
                arlCert.launch(intent);
            }
        });
        v.findViewById(R.id.buttonPemKeyFile).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/x-pem-file");
                arlKey.launch(intent);
            }
        });
        v.findViewById(R.id.buttonPkcs12File).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    String cn = ((EditText) v.findViewById(R.id.editTextCommonNameP12)).getText().toString();
                    String password = ((EditText) v.findViewById(R.id.editTextPassword)).getText().toString();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(null);
                    ks.setKeyEntry(cn, key, password.toCharArray(), new java.security.cert.Certificate[]{cert});
                    ks.store(bos, password.toCharArray());
                    bos.close();
                    p12 = bos.toByteArray();

                    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    intent.addCategory(Intent.CATEGORY_OPENABLE);
                    intent.setType("application/x-pkcs12");
                    intent.putExtra(Intent.EXTRA_TITLE, cn+".p12");
                    arlWriteP12.launch(intent);
                } catch(Exception e) {
                    CommonDialog.show(activity, e.getClass().getName(), e.getMessage(), CommonDialog.Icon.ERROR, false);
                }
            }
        });
        v.findViewById(R.id.buttonPkcs12File).setEnabled(false);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_extras, container, false);
    }

    private String getFileDisplayName(File file, Uri uri) {
        String displayName = "";
        if(uri.toString().startsWith("content://")) {
            Cursor cursor = null;
            try {
                cursor = getActivity().getContentResolver().query(uri, null, null, null, null);
                if(cursor != null && cursor.moveToFirst()) {
                    displayName = cursor.getString(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
                }
            } finally {
                cursor.close();
            }
        } else if(uri.toString().startsWith("file://")) {
            displayName = file.getName();
        }
        return displayName;
    }

}