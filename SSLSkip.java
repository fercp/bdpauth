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
        HttpClient httpClient = HttpClient.create().secure(sslContextSpec -> {
            sslContextSpec.sslContext(SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE));
        });

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }
}
