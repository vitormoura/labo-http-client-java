/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package local.projects.myhttpclient;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import local.projects.myhttpclient.utils.MyOcspChecker;
import local.projects.myhttpclient.utils.HttpProxyConfig;
import local.projects.myhttpclient.utils.SSLCertificateExtractor;

/**
 *
 * @author darkflammeus
 */
public class Program {

    static final String OPT_CMD = "cmd";
    static final String OPT_URL = "url";
    static final String OPT_HOSTPORT = "host";
    static final String OPT_CERTCHAIN_FILEPATH = "certchain_filepath";
    static final String OPT_CERT_FILEPATH = "cert_filepath";
    static final String OPT_KS_FILEPATH = "keystore_filepath";
    static final String OPT_KS_PASSWORD = "keystore_password";
    static final String OPT_PROXY_HOST = "proxy_host";
    static final String OPT_PROXY_PORT = "proxy_port";
    static final Logger logger = Logger.getLogger(Program.class.getName());

    public static void main(String[] args) throws ParseException {

        Options options;

        // Command arg options
        options = new Options();
        options.addRequiredOption("c", "cmd", true, "command to execute")
                .addOption(OPT_URL, true, "test url")
                .addOption(OPT_HOSTPORT, true, "host")
                .addOption(OPT_CERT_FILEPATH, true, "path to certificate")
                .addOption(OPT_CERTCHAIN_FILEPATH, true, "path to certificate ca chain")
                .addOption(OPT_KS_FILEPATH, true, "path to certificate keystore")
                .addOption(OPT_KS_PASSWORD, true, "keystore password")
                .addOption(OPT_PROXY_HOST, true, "proxy host")
                .addOption(OPT_PROXY_PORT, true, "proxy port (default 8080)");

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(options, args);
        String commandName = commandLine.getOptionValue(OPT_CMD).toLowerCase();

        logger.log(Level.INFO, "running {0} command", commandName);

        switch (commandName) {
            case "http:get":
                execHttpGetRequest(commandLine);
                break;

            case "cert:check":
                execCertCheck(commandLine);
                break;

            case "cert:ocsp":
                execCertCheckOCSP(commandLine);
                break;

            case "cert:download":
                execCertDownload(commandLine);
                break;

            default:
                System.err.println("invalid command: " + commandName);
                System.exit(-1);
        }

    }

    public static void execCertDownload(CommandLine cmd) {
        mustHaveRequiredArgs(cmd, new String[]{OPT_HOSTPORT});

        try {

            String url = cmd.getOptionValue(OPT_HOSTPORT);
            SSLCertificateExtractor extractor = new SSLCertificateExtractor(url);
            KeyStore keyStore = null;

            if (hasKeyStoreParams(cmd)) {
                String ksFilepath = cmd.getOptionValue(OPT_KS_FILEPATH);
                String ksPassword = cmd.hasOption(OPT_KS_PASSWORD) ? cmd.getOptionValue(OPT_KS_PASSWORD) : null;

                keyStore = getKeyStore(ksFilepath, ksPassword);
            }

            extractor.run(keyStore);
            
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "error while downloading certificate: " + ex.getMessage(), ex);
        }
    }

    public static void execCertCheck(CommandLine cmd) {

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
        //
        // Valide arguments obligatoires
        //
        mustHaveRequiredArgs(cmd, new String[]{OPT_KS_FILEPATH, OPT_CERT_FILEPATH});

        // 
        // Arguments
        //
        String keyStoreFilePath = cmd.getOptionValue(OPT_KS_FILEPATH);
        String keyStorePassword = cmd.getOptionValue(OPT_KS_PASSWORD);
        String targetCertFile = cmd.getOptionValue(OPT_CERT_FILEPATH);

        // 
        // Variables
        //
        KeyStore keyStore;
        CertificateFactory certFactory;
        X509Certificate targetCert;

        try {

            keyStore = getKeyStore(keyStoreFilePath, keyStorePassword);
            certFactory = CertificateFactory.getInstance("X.509");

            //
            // Ouvre fichier certificat à valider
            // 
            try (FileInputStream in = new FileInputStream(targetCertFile)) {
                targetCert = (X509Certificate) certFactory.generateCertificate(in);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "erreur s'est produite lors de la recharge du certificat", ex);
                System.exit(1);
                return;
            }

            logger.log(Level.INFO, "certificat charg\u00e9: {0} ({1})", new String[]{targetCertFile, targetCert.getSubjectDN().getName()});

            //
            // Valide certificat
            //
            CertPathValidator pathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
            CertPath defaultCertPath = certFactory.generateCertPath(List.of(targetCert));

            PKIXRevocationChecker certPathChecker = (PKIXRevocationChecker) pathValidator.getRevocationChecker();

            // Config validation
            PKIXParameters pathValidatorParams = new PKIXParameters(keyStore);

            pathValidatorParams.addCertPathChecker(certPathChecker);
            pathValidatorParams.setRevocationEnabled(true);

            CertPathValidatorResult pathValidatorResult = pathValidator.validate(defaultCertPath, pathValidatorParams);

            // resultat
            System.out.println(pathValidatorResult.toString());

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "une erreur s'est produite lors de la validation du certificat", ex);
        }
    }

    public static void execHttpGetRequest(CommandLine cmd) {

        mustHaveRequiredArgs(cmd, new String[]{OPT_URL});

        try {

            var client = new local.projects.myhttpclient.utils.MyHttpClient();
            HttpProxyConfig proxyConf = null;

            if (hasKeyStoreParams(cmd)) {

                String ksFilepath = cmd.getOptionValue(OPT_KS_FILEPATH);
                String ksPassword = cmd.hasOption(OPT_KS_PASSWORD) ? cmd.getOptionValue(OPT_KS_PASSWORD) : null;

                KeyStore store = getKeyStore(ksFilepath, ksPassword);

                client.setKeyStore(store);
            }

            // Proxy
            if (cmd.hasOption(OPT_PROXY_HOST)) {
                String proxyHost = cmd.getOptionValue(OPT_PROXY_HOST);
                int proxyPort = Integer.parseInt(cmd.getOptionValue(OPT_PROXY_PORT, "8080"));

                proxyConf = new HttpProxyConfig(proxyPort, proxyHost);
            }

            String response = client.get(new URL(cmd.getOptionValue(OPT_URL)), proxyConf);

            System.out.println(response);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "error while executing http request: " + ex.getMessage(), ex);
        }
    }

    public static void execCertCheckOCSP(CommandLine cmd) {

        mustHaveRequiredArgs(cmd, new String[]{OPT_CERT_FILEPATH, OPT_CERTCHAIN_FILEPATH});

        X509Certificate peerCert;
        X509Certificate issuerCert;

        String certPath = cmd.getOptionValue(OPT_CERT_FILEPATH);
        String issuerPath = cmd.getOptionValue(OPT_CERTCHAIN_FILEPATH);

        try {

            peerCert = getCertificate(certPath);
            issuerCert = getCertificate(issuerPath);

            List<String> ocspUrls = MyOcspChecker.getAIALocations(peerCert);

            // OCSP Request
            Object result = MyOcspChecker.getRevocationStatus(peerCert, issuerCert, 1, ocspUrls);

            // Result
            System.out.printf("Subject: %s\n", peerCert.getSubjectDN());
            System.out.printf("SerialNumber: %s\n", peerCert.getSerialNumber().toString(16));
            System.out.printf("OCSP status: %s\n", result);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "une erreur s'est produite lors du test OCSP", ex);
        }

    }

    private static KeyStore getKeyStore(String keyStoreFilePath, String keyStorePassword) throws Exception {
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

    private static X509Certificate getCertificate(String targetCertFile) throws IOException, FileNotFoundException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate targetCert;

        try (FileInputStream in = new FileInputStream(targetCertFile)) {
            targetCert = (X509Certificate) certFactory.generateCertificate(in);
        }

        logger.log(Level.INFO, "certificate loaded: {0} ({1})", new String[]{targetCertFile, targetCert.getSubjectDN().getName()});

        return targetCert;
    }

    private static void mustHaveRequiredArgs(CommandLine cmd, String[] requiredArgs) {

        for (String arg : requiredArgs) {
            if (!cmd.hasOption(arg)) {
                System.err.println("required argument: " + arg);
                System.exit(1);
            }
        }
    }

    private static boolean hasKeyStoreParams(CommandLine cmd) {
        return cmd.hasOption(OPT_KS_FILEPATH) && cmd.hasOption(OPT_KS_PASSWORD);
    }
}
