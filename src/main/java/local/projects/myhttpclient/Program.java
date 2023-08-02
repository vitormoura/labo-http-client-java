/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package local.projects.myhttpclient;

import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import local.projects.myhttpclient.utils.Certificates;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import local.projects.myhttpclient.utils.MyOcspChecker;
import local.projects.myhttpclient.utils.HttpProxyConfig;
import local.projects.myhttpclient.utils.MyCertificateChecker;
import local.projects.myhttpclient.utils.MyHttpClient;
import local.projects.myhttpclient.utils.MyCertificateExtractor;

/**
 *
 * @author darkflammeus
 */
public class Program {

    static final Logger logger = Logger.getLogger(Program.class.getName());

    static final String OPT_CMD = "cmd";
    static final String OPT_URL = "url";
    static final String OPT_HOSTPORT = "host";
    static final String OPT_CERTCHAIN_FILEPATH = "certchain_filepath";
    static final String OPT_CERT_FILEPATH = "cert_filepath";
    static final String OPT_KS_FILEPATH = "keystore_filepath";
    static final String OPT_KS_PASSWORD = "keystore_password";
    static final String OPT_PROXY_HOST = "proxy_host";
    static final String OPT_PROXY_PORT = "proxy_port";

    public static void main(String[] args) {

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
        CommandLine commandLine;
        String commandName;

        try {

            commandLine = parser.parse(options, args);
            commandName = commandLine.getOptionValue(OPT_CMD).toLowerCase();

        } catch (ParseException ex) {
            logger.log(Level.SEVERE, "error while parsing the command line", ex);

            System.exit(-1);
            return;
        }

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
            MyCertificateExtractor extractor = new MyCertificateExtractor(url);
            KeyStore keyStore = null;

            if (hasKeyStoreParams(cmd)) {
                String ksFilepath = cmd.getOptionValue(OPT_KS_FILEPATH);
                String ksPassword = cmd.hasOption(OPT_KS_PASSWORD) ? cmd.getOptionValue(OPT_KS_PASSWORD) : null;

                keyStore = Certificates.getKeyStore(ksFilepath, ksPassword);
            }

            extractor.run(keyStore);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "error while downloading certificate: " + ex.getMessage(), ex);
        }
    }

    public static void execCertCheck(CommandLine cmd) {
        mustHaveRequiredArgs(cmd, new String[]{OPT_KS_FILEPATH, OPT_CERT_FILEPATH});

        String keyStoreFilePath = cmd.getOptionValue(OPT_KS_FILEPATH);
        String keyStorePassword = cmd.getOptionValue(OPT_KS_PASSWORD);
        String targetCertFile = cmd.getOptionValue(OPT_CERT_FILEPATH);

        try {

            MyCertificateChecker checker = new MyCertificateChecker(keyStoreFilePath, keyStorePassword);
            String result = checker.check(targetCertFile, true);

            System.out.println(result);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "error while validating certificate: " + ex.getMessage(), ex);
        }
    }

    public static void execHttpGetRequest(CommandLine cmd) {
        mustHaveRequiredArgs(cmd, new String[]{OPT_URL});

        try {

            MyHttpClient client = new local.projects.myhttpclient.utils.MyHttpClient();

            if (hasKeyStoreParams(cmd)) {

                var ksFilepath = cmd.getOptionValue(OPT_KS_FILEPATH);
                var ksPassword = cmd.hasOption(OPT_KS_PASSWORD) ? cmd.getOptionValue(OPT_KS_PASSWORD) : null;
                var ks = Certificates.getKeyStore(ksFilepath, ksPassword);

                client.setKeyStore(ks);
            }

            client.setProxyConf(getProxyConfigFrom(cmd));

            var url = new URL(cmd.getOptionValue(OPT_URL));
            var response = client.get(url);

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

            peerCert = Certificates.loadFromFile(certPath);
            issuerCert = Certificates.loadFromFile(issuerPath);

            List<String> ocspUrls = MyOcspChecker.getAIALocations(peerCert);

            // OCSP Request
            MyOcspChecker checker = new MyOcspChecker();
            checker.setProxy(getProxyConfigFrom(cmd));

            String result = checker.getRevocationStatus(peerCert, issuerCert, 1, ocspUrls);

            // Result
            System.out.printf("Subject: %s\n", peerCert.getSubjectDN());
            System.out.printf("SerialNumber: %s\n", peerCert.getSerialNumber().toString(16));
            System.out.printf("OCSP status: %s\n", result);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "error while checking OCSP: " + ex.getMessage(), ex);
        }

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
    
    private static HttpProxyConfig getProxyConfigFrom(CommandLine cmd) {
        if (!cmd.hasOption(OPT_PROXY_HOST)) {
            return null;
        }

        var proxyHost = cmd.getOptionValue(OPT_PROXY_HOST);
        var proxyPort = Integer.parseInt(cmd.getOptionValue(OPT_PROXY_PORT, "8080"));

        return new HttpProxyConfig(proxyPort, proxyHost);
    }
}
