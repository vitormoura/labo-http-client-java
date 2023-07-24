/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package local.projects.myhttpclient;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
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
import javax.net.ssl.SSLContext;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import local.projects.myhttpclient.utils.CertificateUtils;

/**
 *
 * @author darkflammeus
 */
public class MyHttpClient {

    static final String OPT_CMD = "cmd";
    static final String OPT_CERTCHAIN_FILEPATH = "certchain_filepath";
    static final String OPT_CERT_FILEPATH = "cert_filepath";
    static final String OPT_KS_FILEPATH = "keystore_filepath";
    static final String OPT_KS_PASSWORD = "keystore_password";
    static final String OPT_PROXY_HOST = "proxy_host";
    static final String OPT_PROXY_PORT = "proxy_port";
    static final Logger logger = Logger.getLogger(MyHttpClient.class.getName());

    public static void main(String[] args) throws ParseException {

        Options options;

        // Command arg options
        options = new Options();
        options.addRequiredOption("c", "cmd", true, "command to execute")
                .addOption("u", "url", true, "test url")
                .addOption(OPT_CERT_FILEPATH, true, "path to certificate")
                .addOption(OPT_CERTCHAIN_FILEPATH, true, "path to certificate ca chain")
                .addOption(OPT_KS_FILEPATH, true, "path to certificate keystore")
                .addOption(OPT_KS_PASSWORD, true, "keystore password")
                .addOption(OPT_PROXY_HOST, true, "proxy host")
                .addOption(OPT_PROXY_PORT, true, "proxy port (default 8080)");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        String cmdToExec = cmd.getOptionValue(OPT_CMD).toLowerCase();

        switch (cmdToExec) {
            case "http:get":
                execHttpGetRequest(cmd);
                break;

            case "cert:check":
                execCertCheck(cmd);
                break;

            case "cert:ocsp":
                execCertCheckOCSP(cmd);
                break;

            default:
                System.err.println("ERR invalid command: " + cmdToExec);
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
        String[] requiredArgs = new String[]{OPT_KS_FILEPATH, OPT_CERT_FILEPATH};

        for (String arg : requiredArgs) {
            if (!cmd.hasOption(arg)) {
                System.err.println("required argument: " + arg);
                System.exit(1);
            }
        }

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
        try {

            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if (cmd.hasOption(OPT_KS_FILEPATH) && cmd.hasOption(OPT_KS_PASSWORD)) {

                File keystoreFile = new File(cmd.getOptionValue(OPT_KS_FILEPATH));

                if (!keystoreFile.exists()) {
                    System.err.println("Invalid keystore path: " + keystoreFile.getAbsolutePath());
                    return;
                }

                sslContextBuilder.loadTrustMaterial(
                        keystoreFile,
                        cmd.hasOption(OPT_KS_PASSWORD) ? cmd.getOptionValue(OPT_KS_PASSWORD).toCharArray() : null,
                        new TrustSelfSignedStrategy()
                );
            }

            SSLContext sslcontext;
            sslcontext = sslContextBuilder.build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslcontext,
                    null,
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );

            HttpClientBuilder httpClientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);

            // Proxy
            if (cmd.hasOption(OPT_PROXY_HOST)) {
                String proxyHost = cmd.getOptionValue(OPT_PROXY_HOST);
                String proxyPort = cmd.getOptionValue(OPT_PROXY_PORT, "8080");

                logger.log(Level.INFO, "using proxy config: {0}:{1}", new Object[]{proxyHost, proxyPort});

                HttpHost proxy = new HttpHost(proxyHost, Integer.parseInt(proxyPort));
                DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);

                httpClientBuilder.setRoutePlanner(routePlanner);
            }

            CloseableHttpClient httpclient = httpClientBuilder.build();

            try {

                HttpGet httpget = new HttpGet(cmd.getOptionValue("url"));

                logger.log(Level.INFO, "executing {0}", httpget.getRequestLine());

                CloseableHttpResponse response = httpclient.execute(httpget);

                try {
                    HttpEntity entity = response.getEntity();

                    logger.log(Level.INFO, "http response {0}", response.getStatusLine());

                    System.out.println(EntityUtils.toString(entity));

                } finally {
                    response.close();
                }
            } finally {
                httpclient.close();
            }

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | KeyManagementException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }

    public static void execCertCheckOCSP(CommandLine cmd) {

        X509Certificate cert;
        X509Certificate issuerCert;
                
        String certPath = cmd.getOptionValue(OPT_CERT_FILEPATH);
        String issuerPath = cmd.getOptionValue(OPT_CERTCHAIN_FILEPATH);

        try {
            cert = getCertificate(certPath);
            issuerCert = getCertificate(issuerPath);
            
            List<String> ocspUrls = CertificateUtils.getAIALocations(issuerCert);
                                   
            
            // OCSP Request
            Object result = CertificateUtils.getRevocationStatus(cert, issuerCert, 0, ocspUrls);
            
            
            System.out.println(result);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "une erreur s'est produite lors du test OCSP",ex);
        }            

    }

    private static KeyStore getKeyStore(String keyStoreFilePath, String keyStorePassword) throws Exception {
        KeyStore keyStore;
        File certStoreFile = new File(keyStoreFilePath);

        try {

            char[] keystorePasswordChars = keyStorePassword != null ? keyStorePassword.toCharArray() : null;
            keyStore = KeyStore.getInstance(certStoreFile, keystorePasswordChars);

            logger.log(Level.INFO, "keystore charg\u00e9: {0}", keyStoreFilePath);

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

        logger.log(Level.INFO, "certificat charg\u00e9: {0} ({1})", new String[]{targetCertFile, targetCert.getSubjectDN().getName()});

        return targetCert;
    }    
    
}
