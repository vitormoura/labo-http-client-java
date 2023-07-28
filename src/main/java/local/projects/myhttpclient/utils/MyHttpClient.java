package local.projects.myhttpclient.utils;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
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

    static final Logger logger = Logger.getLogger(MyHttpClient.class.getName());

    private KeyStore keyStore;

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public String get(URL url, HttpProxyConfig proxyConf) throws IOException {

        SSLContext sslcontext;
        SSLContextBuilder sslContextBuilder = SSLContexts.custom();

        try {
            
            KeyStore certStore = this.getKeyStore();

            if (certStore != null) {
                logger.log(Level.INFO, "loading keyStore as sslContext trustMaterial");
                sslContextBuilder.loadTrustMaterial(certStore, null);
            }
            
            sslcontext = sslContextBuilder.build();

        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException ex) {
            logger.log(Level.SEVERE, "error while creating sslContext: " + ex.getMessage(), ex);
            return "";
        }
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                sslcontext,
                null,
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );

        HttpClientBuilder httpClientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);
        

        // Proxy
        if (proxyConf != null) {
            logger.log(Level.INFO, "using proxy config: {0}:{1}", new Object[]{proxyConf.getHost(), proxyConf.getPort()});

            HttpHost proxy = proxyConf.toHttpHost();
            DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);

            httpClientBuilder.setRoutePlanner(routePlanner);
        }

        try (CloseableHttpClient httpclient = httpClientBuilder.build()) {

            HttpGet httpget = new HttpGet(url.toString());

            logger.log(Level.INFO, "executing {0}", httpget.getRequestLine());

            try (CloseableHttpResponse response = httpclient.execute(httpget)) {
                HttpEntity entity = response.getEntity();

                logger.log(Level.INFO, "http response {0}", response.getStatusLine());

                return EntityUtils.toString(entity);
            }
        }
    }
}
