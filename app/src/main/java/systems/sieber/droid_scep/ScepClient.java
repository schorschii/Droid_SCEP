package systems.sieber.droid_scep;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import java.net.URL;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.jscep.client.Client;

import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionException;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class ScepClient {

    public static class BadRequestException extends Exception {}

    public static byte[] CertReq(String enrollentURL, String entityName, String enrollmentChallenge, int isKeyLen, String keystoreAlias, String keystorePassword)
            throws BadRequestException, ClientException, TransactionException, CertStoreException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, KeyStoreException, NoSuchProviderException, IOException {

        // load SpongyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        URL server = new URL(enrollentURL);

        CertificateVerifier verifier = new OptimisticCertificateVerifier();
        Client client = new Client(server, verifier);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        keyGen.initialize(isKeyLen);
        KeyPair keyPair = keyGen.genKeyPair();

        X500Name entity = new X500Name(entityName);

        // create a self signed cert to sign the PKCS7 envelope
        JcaX509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
                entity, BigInteger.valueOf(1), new Date(
                System.currentTimeMillis()), new Date(
                System.currentTimeMillis()
                        + (1000L * 60 * 60 * 24 * 100)), entity,
                keyPair.getPublic());

        JcaContentSignerBuilder csb = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner cs = csb.build(keyPair.getPrivate());
        X509CertificateHolder certH = v3CertGen.build(cs);
        JcaX509CertificateConverter conVert = new JcaX509CertificateConverter();
        X509Certificate cert = conVert.getCertificate(certH);

        // generate the CSR
        PKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(
                entity, keyPair.getPublic());

        // set the password
        DERPrintableString password = new DERPrintableString(enrollmentChallenge);
        crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);

        // Send the enrollment request
        EnrollmentResponse response = client.enrol(cert, keyPair.getPrivate(), crb.build(cs), "NDESCA");

        Certificate certz[] = new Certificate[1];
        // Automatic enrollment, so this should be issued
        if(!response.isSuccess()) {
            if(response.getFailInfo() == FailInfo.badRequest)
                throw new BadRequestException();
            else
                throw new ClientException(response.getFailInfo().toString());
        }

        CertStore store = response.getCertStore();
        Collection<? extends Certificate> certs = store.getCertificates(null);

        @SuppressWarnings("unchecked")
        Iterator<Certificate> ir = (Iterator<Certificate>) certs.iterator();

        int i = 0;
        while(ir.hasNext()) {
            certz[i] = ir.next();
            System.out.println(certz[i]);
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);

        Key k = keyPair.getPrivate();
        keyStore.setKeyEntry(keystoreAlias, k, keystorePassword.toCharArray(), certz);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        keyStore.store(bout, keystorePassword.toCharArray()); // this is the password to open the .p12

        byte[] keystore = bout.toByteArray();
        bout.close();

        return keystore;

    }
}
