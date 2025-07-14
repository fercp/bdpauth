import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.SslProvider;
import io.netty.handler.ssl.SslContextBuilder;
import javax.net.ssl.SSLException;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient() throws SSLException {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
        };

        SSLContext javaSslContext = SSLContext.getInstance("TLS");
        javaSslContext.init(null, trustAllCerts, new SecureRandom());

// Wrap Java SSLContext in a Netty JdkSslContext
        SslContext nettySslContext = new JdkSslContext(
                javaSslContext,
                true, // isClient
                ClientAuth.NONE
    }
}
