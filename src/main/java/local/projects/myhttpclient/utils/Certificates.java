/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package local.projects.myhttpclient.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import local.projects.myhttpclient.Program;

/**
 *
 * @author darkflammeus
 */
public final class Certificates {
    
    static final Logger logger = Logger.getLogger(Program.class.getName());
    
    private Certificates() {
        throw new AssertionError();
    }
    
    public static X509Certificate loadFromFile(String targetCertFile) throws IOException, FileNotFoundException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate targetCert;

        try (FileInputStream in = new FileInputStream(targetCertFile)) {
            targetCert = (X509Certificate) certFactory.generateCertificate(in);
        }

        logger.log(Level.INFO, "certificate loaded: {0} ({1})", new String[]{targetCertFile, targetCert.getSubjectDN().getName()});

        return targetCert;
    }
        
    public static KeyStore getKeyStore(String keyStoreFilePath, String keyStorePassword) throws Exception {
        KeyStore keyStore;
        File certStoreFile = new File(keyStoreFilePath);

        try {

            char[] keystorePasswordChars = keyStorePassword != null ? keyStorePassword.toCharArray() : null;
            keyStore = KeyStore.getInstance(certStoreFile, keystorePasswordChars);

            logger.log(Level.INFO, "keystore loaded: {0}", keyStoreFilePath);

            return keyStore;

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            throw ex;
        }
    }
    
    public static KeyStore getDefaultKeyStore() throws Exception {
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        String password = "changeit";
        
        return getKeyStore(filename, password);
    }
    
}
