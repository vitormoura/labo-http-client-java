/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package local.projects.myhttpclient;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
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

/**
 *
 * @author darkflammeus
 */
public class MyHttpClient {

    public static void main(String[] args) throws ParseException {

        Logger logger = Logger.getLogger(MyHttpClient.class.getName());
        SSLContext sslcontext;
        Options options;

        final String OPT_KS_FILEPATH = "keystore_filepath";
        final String OPT_KS_PASSWORD = "keystore_password";
        final String OPT_PROXY_HOST = "proxy_host";
        final String OPT_PROXY_PORT = "proxy_port";

        // Command arg options
        options = new Options();
        options.addRequiredOption("u", "url", true, "test url")
                .addOption(OPT_KS_FILEPATH, true, "path to certificate keystore")
                .addOption(OPT_KS_PASSWORD, true, "keystore password")
                .addOption(OPT_PROXY_HOST, true, "proxy host")
                .addOption(OPT_PROXY_PORT, true, "proxy port (default 8080)");

        try {

            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

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

            sslcontext = sslContextBuilder.build();

            // Allow TLSv1 protocol only
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslcontext,
                    null,
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier());

            HttpClientBuilder httpClientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);

            // Proxy
            if (cmd.hasOption(OPT_PROXY_HOST)) {
                String proxyHost = cmd.getOptionValue(OPT_PROXY_HOST);
                String proxyPort = cmd.getOptionValue(OPT_PROXY_PORT, "8080");

                logger.log(Level.FINE, "using proxy config: {0}:{1}", new Object[]{proxyHost, proxyPort});

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

                    System.out.println(
                            EntityUtils.toString(entity)
                    );

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

}
