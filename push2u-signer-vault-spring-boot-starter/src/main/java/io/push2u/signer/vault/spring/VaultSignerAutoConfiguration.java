package io.push2u.signer.vault.spring;

import io.push2u.PushHttpClient;
import io.push2u.VapidSigner;
import io.push2u.signer.vault.VaultTransitVapidSigner;
import java.util.Base64;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Autoconfigures a {@link VaultTransitVapidSigner} as the {@link VapidSigner} from
 * {@code push2u.signer.vault.*}. Active when {@code address}, {@code key-name} and {@code token} are
 * set; {@code public-key} is optional — when omitted (or blank) the signer reads its public key from
 * {@code transit/keys/<key>} at startup (the recommended single-source-of-truth mode; the token then
 * needs {@code read} on the key), and when supplied the signer uses it verbatim (token needs only
 * {@code sign}).
 *
 * <p>Ordered before the core starter's {@code Push2uAutoConfiguration} (by name, so this module
 * need not depend on it) and {@link ConditionalOnMissingBean}: when both starters are present this
 * remote signer wins over the in-JVM local signer, while an application-supplied {@link VapidSigner}
 * still overrides both. The Vault {@code sign} calls reuse an application {@link PushHttpClient} bean
 * if present.
 */
@AutoConfiguration(beforeName = "io.push2u.spring.Push2uAutoConfiguration")
@EnableConfigurationProperties(VaultSignerProperties.class)
public final class VaultSignerAutoConfiguration {

    VaultSignerAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The Vault Transit signer, built from {@code push2u.signer.vault.*}. Absent unless the address,
     * key name, token and public key are all set, and yields to an application-supplied signer.
     *
     * @param properties the bound configuration
     * @param httpClient an optional application HTTP transport for the Vault calls
     * @return the signer
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(prefix = "push2u.signer.vault", name = {"address", "key-name", "token"})
    VapidSigner vaultTransitVapidSigner(VaultSignerProperties properties, ObjectProvider<PushHttpClient> httpClient) {
        PushHttpClient client = httpClient.getIfAvailable();
        String publicKey = properties.publicKey();
        if (publicKey == null || publicKey.isBlank()) {
            // Fetched mode: the signer reads the public key from transit/keys/<key> at construction,
            // keeping the Transit key the single source of truth (the token needs `read` on the key).
            return client == null
                ? new VaultTransitVapidSigner(
                    properties.address(), properties.mount(), properties.keyName(), properties.token())
                : new VaultTransitVapidSigner(
                    properties.address(), properties.mount(), properties.keyName(), properties.token(), client);
        }
        // Explicit mode: the published public key is supplied; the token needs only `sign`.
        byte[] point = Base64.getUrlDecoder().decode(publicKey);
        return client == null
            ? new VaultTransitVapidSigner(
                properties.address(), properties.mount(), properties.keyName(), properties.token(), point)
            : new VaultTransitVapidSigner(
                properties.address(), properties.mount(), properties.keyName(), properties.token(), point, client);
    }
}
