/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package local.projects.myhttpclient.utils;

import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author darkflammeus
 */
public class MyCertificateChecker {

    static final Logger logger = Logger.getLogger(MyCertificateChecker.class.getName());

    private final String keyStoreFilePath;
    private final String keyStorePassword;

    public MyCertificateChecker(String keyStoreFilePath, String keyStorePassword) {
        this.keyStoreFilePath = keyStoreFilePath;
        this.keyStorePassword = keyStorePassword;
    }

    public String check(String certFilePath, boolean checkRevocation) throws Exception {

        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html
        // CertPath
        // CertificateFactory: Peut créer des CertPaths depuis des listes de certificats ou des fichiers (generateCertPath)
        // CertPathParameters (PKIXParameters)
        // CertPathValidator
        // CertPathValidatorResult
        // CertPathBuilder
        // CertPathBuilderResult
        // CertStore (CertSelector, CRLSelector, X509CertSelector,X509CertSelector)
        // X509CertSelector
        // TrustAnchor
        // PKIXBuilderParameters 
        // PKIXCertPathChecker
        // PKIXRevocationChecker   
                
        KeyStore keyStore = Certificates.getKeyStore(keyStoreFilePath, keyStorePassword);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate targetCert = Certificates.loadFromFile(certFilePath);
        
        //
        // Valide certificat
        //
        
        CertPathValidator pathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
        CertPath defaultCertPath = certFactory.generateCertPath(List.of(targetCert));

        PKIXRevocationChecker certPathChecker = (PKIXRevocationChecker) pathValidator.getRevocationChecker();

        // Config validation
        PKIXParameters pathValidatorParams = new PKIXParameters(keyStore);

        pathValidatorParams.addCertPathChecker(certPathChecker);
        pathValidatorParams.setRevocationEnabled(checkRevocation);

        logger.log(Level.INFO, "executing certificate validation (check revocation: {0})", checkRevocation);
        
        var pathValidatorResult = pathValidator.validate(defaultCertPath, pathValidatorParams);

        return pathValidatorResult.toString();

    }
}
