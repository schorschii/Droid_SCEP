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
import java.security.MessageDigest;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.jscep.client.Client;

import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.MessageDigestCertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;

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
    public static class CertReqResponse {
        CertStore mCertStore;
        PrivateKey mPrivKey;
        public CertReqResponse(CertStore certStore, PrivateKey privKey) {
            mCertStore = certStore;
            mPrivKey = privKey;
        }
    }

    public static CertReqResponse CertReq(String enrollmentURL, String entityName, String upn, String enrollmentChallenge, String caFingerprint, String enrollmentProfile, int isKeyLen)
            throws BadRequestException, RequestPendingException, ClientException, TransactionException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {

        // load SpongyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        // check CA fingerprint
        CertificateVerifier verifier;
        if(caFingerprint == null || caFingerprint.isEmpty()) {
            verifier = new OptimisticCertificateVerifier();
        } else {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] expected = Hex.decode(caFingerprint.getBytes());
            verifier = new MessageDigestCertificateVerifier(digest, expected);
        }

        // init SCEP client
        URL server = new URL(enrollmentURL);
        Client client = new Client(server, verifier);

        // generate key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(isKeyLen);
        KeyPair keyPair = keyGen.genKeyPair();

        // create a self signed cert to sign the PKCS7 envelope
        X500Name entity = new X500Name(entityName);
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

        // add Subject Alt Name
        ArrayList<GeneralName> names = new ArrayList<>();
        if(upn != null && !upn.isEmpty()) {
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

        // set the password
        DERPrintableString password = new DERPrintableString(enrollmentChallenge);
        crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);

        // send the enrollment request
        EnrollmentResponse response = client.enrol(cert, keyPair.getPrivate(), crb.build(cs), enrollmentProfile);
        if(!response.isSuccess()) {
            if(response.isPending()) {
                throw new RequestPendingException(
                        cert2pem(cert, false),
                        key2pem(keyPair.getPrivate(), false),
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

        return new CertReqResponse(response.getCertStore(), keyPair.getPrivate());
    }

    public static CertReqResponse CertPoll(String enrollmentURL, String certPem, String keyPem, String entityName, String transactionId)
            throws BadRequestException, RequestPendingException, ClientException, TransactionException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException {

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
                        cert2pem(cert, false),
                        key2pem(key, false),
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

        return new CertReqResponse(response.getCertStore(), key);
    }

    public static byte[] certResponse2pkcs12(CertStore store, PrivateKey key, String keystoreAlias, String keystorePassword)
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

    static String csr2pem(PKCS10CertificationRequest csr, boolean withTags) throws IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.encode(csr.getEncoded(), 0, csr.getEncoded().length, s);
        if(withTags) {
            return "-----BEGIN NEW CERTIFICATE REQUEST-----\n" + s.toString() + "\n-----END NEW CERTIFICATE REQUEST-----\n";
        } else {
            return s.toString();
        }
    }
    static String cert2pem(X509Certificate cert, boolean withTags) throws CertificateEncodingException, IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.encode(cert.getEncoded(), 0, cert.getEncoded().length, s);
        if(withTags) {
            return "-----BEGIN CERTIFICATE-----\n" + s.toString() + "\n-----END CERTIFICATE-----\n";
        } else {
            return s.toString();
        }
    }
    static String key2pem(PrivateKey key, boolean withTags) throws IOException {
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.encode(key.getEncoded(), 0, key.getEncoded().length, s);
        if(withTags) {
            return "-----BEGIN PRIVATE KEY-----\n" + s.toString() + "\n-----END PRIVATE KEY-----\n";
        } else {
            return s.toString();
        }
    }
    static X509Certificate pem2cert(String pem) throws CertificateException, IOException {
        pem = stripPem(pem);
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.decode(pem.getBytes(), 0, pem.getBytes().length, s);
        InputStream is = new ByteArrayInputStream(s.toByteArray());
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(is);
    }
    static PrivateKey pem2key(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        pem = stripPem(pem);
        Base64Encoder encoder = new Base64Encoder();
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        encoder.decode(pem.getBytes(), 0, pem.getBytes().length, s);
        return (PrivateKey) KeyFactory
                .getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(s.toByteArray()));
    }
    private static String stripPem(String pem) {
        pem = pem.trim();
        if(pem.startsWith("-----BEGIN PRIVATE KEY-----")) {
            pem = pem.substring("-----BEGIN PRIVATE KEY-----".length());
        }
        if(pem.startsWith("-----BEGIN CERTIFICATE-----")) {
            pem = pem.substring("-----BEGIN CERTIFICATE-----".length());
        }
        if(pem.endsWith("-----END PRIVATE KEY-----")) {
            pem = pem.substring(0, pem.length() - "-----END PRIVATE KEY-----".length());
        }
        if(pem.endsWith("-----END CERTIFICATE-----")) {
            pem = pem.substring(0, pem.length() - "-----END CERTIFICATE-----".length());
        }
        return pem.trim();
    }

}
