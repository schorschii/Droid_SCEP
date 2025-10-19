package systems.sieber.droid_scep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import java.net.URL;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
import org.jscep.transaction.TransactionId;
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
import org.spongycastle.util.encoders.Base64Encoder;

import javax.security.auth.x500.X500Principal;

public class ScepClient {

    public static class BadRequestException extends Exception {}
    public static class RequestPendingException extends Exception {
        String mTransactionId;
        String mCert;
        String mKey;
        RequestPendingException(String cert, String key, String transactionId) {
            mCert = cert;
            mKey = key;
            mTransactionId = transactionId;
        }
        String getCertPem() {
            return mCert;
        }
        String getKeyPem() {
            return mKey;
        }
        String getTransactionId() {
            return mTransactionId;
        }
    }

    public static byte[] CertReq(String enrollmentURL, String entityName, String enrollmentChallenge, String enrollmentProfile, int isKeyLen, String keystoreAlias, String keystorePassword)
            throws BadRequestException, RequestPendingException, ClientException, TransactionException, CertStoreException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, KeyStoreException, NoSuchProviderException, IOException {

        // load SpongyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        URL server = new URL(enrollmentURL);

        CertificateVerifier verifier = new OptimisticCertificateVerifier();
        Client client = new Client(server, verifier);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        keyGen.initialize(isKeyLen);
        KeyPair keyPair = keyGen.genKeyPair();

        X500Name entity = new X500Name(entityName);

        // create a self signed cert to sign the PKCS7 envelope
        JcaX509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
                entity, BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
                entity,
                keyPair.getPublic()
        );

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

        // send the enrollment request
        EnrollmentResponse response = client.enrol(cert, keyPair.getPrivate(), crb.build(cs), enrollmentProfile);
        if(!response.isSuccess()) {
            if(response.isPending()) {
                throw new RequestPendingException(
                        cert2pem(cert),
                        key2pem(keyPair.getPrivate()),
                        response.getTransactionId().toString()
                );
            } else if(response.isFailure()) {
                if(response.getFailInfo() == FailInfo.badRequest)
                    throw new BadRequestException();
                else
                    throw new ClientException(response.getFailInfo().toString());
            }
            throw new ClientException("Response is neither success, pending or failure?!");
        }

        return parseCertResponse(response.getCertStore(), keyPair.getPrivate(), keystoreAlias, keystorePassword);
    }

    public static byte[] CertPoll(String enrollmentURL, String certPem, String keyPem, String entityName, String transactionId, String keystoreAlias, String keystorePassword)
            throws BadRequestException, RequestPendingException, ClientException, TransactionException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException, CertStoreException, KeyStoreException, NoSuchProviderException {

        // load SpongyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        URL server = new URL(enrollmentURL);

        CertificateVerifier verifier = new OptimisticCertificateVerifier();
        Client client = new Client(server, verifier);

        X500Principal entity = new X500Principal(entityName);
        X509Certificate cert = pem2cert(certPem);
        PrivateKey key = pem2key(keyPem);

        TransactionId tId = new TransactionId(transactionId.getBytes());
        EnrollmentResponse response = client.poll(cert, key, entity, tId);

        if(!response.isSuccess()) {
            if(response.isPending()) {
                throw new RequestPendingException(
                        cert2pem(cert),
                        key2pem(key),
                        response.getTransactionId().toString()
                );
            } else if(response.isFailure()) {
                if(response.getFailInfo() == FailInfo.badRequest)
                    throw new BadRequestException();
                else
                    throw new ClientException(response.getFailInfo().toString());
            }
            throw new ClientException("Response is neither success, pending or failure?!");
        }

        return parseCertResponse(response.getCertStore(), key, keystoreAlias, keystorePassword);
    }

    private static byte[] parseCertResponse(CertStore store, PrivateKey key, String keystoreAlias, String keystorePassword)
            throws CertStoreException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException {
        Collection<? extends Certificate> certs = store.getCertificates(null);

        @SuppressWarnings("unchecked")
        Iterator<Certificate> ir = (Iterator<Certificate>) certs.iterator();
        Certificate certz[] = new Certificate[1];
        int i = 0;
        while(ir.hasNext()) {
            certz[i] = ir.next();
            System.out.println(certz[i]);
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);

        keyStore.setKeyEntry(keystoreAlias, key, keystorePassword.toCharArray(), certz);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        keyStore.store(bout, keystorePassword.toCharArray()); // this is the password to open the .p12

        byte[] keystore = bout.toByteArray();
        bout.close();

        return keystore;
    }

    private static String cert2pem(X509Certificate cert) throws CertificateEncodingException, IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.encode(cert.getEncoded(), 0, cert.getEncoded().length, s);
        return s.toString();
        //return "-----BEGIN CERTIFICATE-----\n" + s.toString() + "-----END CERTIFICATE-----\n";
    }
    private static String key2pem(PrivateKey key) throws IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.encode(key.getEncoded(), 0, key.getEncoded().length, s);
        return s.toString();
        //return "-----BEGIN PRIVATE KEY-----\n" + s.toString() + "-----END PRIVATE KEY-----\n";
    }
    private static X509Certificate pem2cert(String pem) throws CertificateException, IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.decode(pem.getBytes(), 0, pem.getBytes().length, s);
        InputStream is = new ByteArrayInputStream(s.toByteArray());
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(is);
    }
    private static PrivateKey pem2key(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.decode(pem.getBytes(), 0, pem.getBytes().length, s);
        return (PrivateKey) KeyFactory
                .getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(s.toByteArray()));
    }

}
