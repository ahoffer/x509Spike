package org.codice.ddf.certificate;

import com.sun.tools.javac.util.Convert;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SignedCertificate {

    private static final long MILLIS_IN_DAY = 86400000;
    private static final long MILLIS_IN_YEAR = 31536000000L;
    private static String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args) throws Exception {

        //Register the Bouncy Castle service provider
        Security.addProvider(new BouncyCastleProvider());

        //Cache any concerter objects used more than once.
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider(BC);


        //Load Demo DDF  Certificate Authority's cert.
        String cacertFilename = "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/certs/demoCA/cacert.pem";
        X509CertificateHolder certificateAuthorityCertHolder = (X509CertificateHolder) getPemObjectFromFile(cacertFilename);
        X509Certificate certificateAuthorityCert = certificateConverter.getCertificate(certificateAuthorityCertHolder);

        //Load Demo DDF Certificate Authority's private key into memory.
        String certificateAuthorityKeyNoPassword = "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/certs/demoCA/private/cakey-nopassword.pem";
        PrivateKey caPrivateKey = pemFile2PrivateKey(certificateAuthorityKeyNoPassword);

        //Generate a public and private
        // keypair for a new certificate
        KeyPair thisKp = getKeyPair();

        //Create the Certificate Signing Request
        X509v3CertificateBuilder csr = getCertificateSigningRequest(getHostname(), thisKp.getPublic(), certificateAuthorityCert);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(caPrivateKey);
        X509CertificateHolder thisCertHolder = csr.build(sigGen);
        X509Certificate cert = certificateConverter.getCertificate(thisCertHolder);

        //TODO: Save the new certificate out to disk and test with it. Test with openssl, test with keytool. Finally, swap it for current cert. If it works, automate importing it into keystore.
        //TODO: Look at verificiation checks in lines 1405-1444 in CertTest.java for more tests.
        cert.checkValidity(new Date());
        cert.verify(certificateAuthorityCert.getPublicKey());
        cert.verify(cert.getPublicKey());

    }//end method

    //Create certificate signing request
    public static X509v3CertificateBuilder getCertificateSigningRequest(String fqdn, PublicKey subjectPubKey, X509Certificate issuerCert) throws OperatorCreationException, CertificateException {

        //Build subject for the certificate
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.C, "US");  //two letter country code
        nameBuilder.addRDN(BCStyle.CN, fqdn); //common name must be the machine's fully qualified domain name
        X500Name subject = nameBuilder.build();

        //Public constructor methods.
        //  public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey)
        //  public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, PublicKey publicKey)
        //  public JcaX509v3CertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey)

        X509v3CertificateBuilder csr = new JcaX509v3CertificateBuilder(
                issuerCert,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - MILLIS_IN_YEAR),
                new Date(System.currentTimeMillis() + MILLIS_IN_YEAR),
                subject,
                subjectPubKey);


        return csr;
    }

    //Create a new RSA key pair.
    private static KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BC);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    //Does exactly what it says on the tin.
    public static PrivateKey pemFile2PrivateKey(String filename) throws IOException {
        //See to https://tools.ietf.org/html/rfc5208#page-3 learn about the standard describing private key.
/*      "[RFC 5208] describes a syntax for private-key information.
        Private-key information includes a private key for some public-key
        algorithm and a set of attributes.  The document also describes a
        syntax for encrypted private keys.  A password-based encryption
        algorithm (e.g., one of those described in [PKCS#5]) could be used to
        encrypt the private-key information."
*/
        //Get a handle to a local file.
        FileInputStream fis = new FileInputStream(filename);

        //Load and parse PEM object
        PEMParser pemRd = new PEMParser(new InputStreamReader(fis));
        Object objectInPemFile = pemRd.readObject();

        //The magic PEM parser should parser should return and instance of PrivateKeyInfo.
        //If this is a problem, the PEM file is probably password protected.
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) objectInPemFile;

        //Extract private key from key info object.
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC);
        return converter.getPrivateKey(privateKeyInfo);
    }

    //Does exactly what it says on the tin.
    public static String getHostname() {
        String str = "uninitialized";
        try {
            str = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        return str;
    }//end method

    //Does exactly what it says on the tin.
    private static void printSecurityProviderInfo() {
        //Dump provider information to console.
        Provider[] providers = Security.getProviders();
        System.out.println("------------------------");
        for (Provider each : providers) {
            System.out.println(each.getName() + " - " + each.getInfo());
            System.out.println("------------------------");
        }
    }

    //Given a filename, attempt to return the first PEM object in the file.
    //Die hard is there is an error.
    private static Object getPemObjectFromFile(String filename) {
        PEMParser pem;
        Object firstObjectInFile = null;
        try {
            pem = new PEMParser(new InputStreamReader(new FileInputStream(filename)));
            firstObjectInFile = pem.readObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return firstObjectInFile;

    }//end method

}//end class