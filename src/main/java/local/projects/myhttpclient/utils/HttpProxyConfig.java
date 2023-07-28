package local.projects.myhttpclient.utils;

import org.apache.http.HttpHost;

/**
 *
 * @author darkflammeus
 */
public class HttpProxyConfig {
    private final int port;
    private final String host;
    private String userName;
    private String password;

    public int getPort() {
        return port;
    }

    public String getHost() {
        return host;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
        
    public HttpProxyConfig(int port, String host) {
        this.port = port;
        this.host = host;
    }
    
    public HttpHost toHttpHost() {
        return new HttpHost(getHost(), getPort());
    }
}
