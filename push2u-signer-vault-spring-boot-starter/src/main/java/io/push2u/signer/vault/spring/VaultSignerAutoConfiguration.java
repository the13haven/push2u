package io.push2u.signer.vault.spring;

import java.net.http.HttpClient;
import java.util.Base64;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import io.push2u.VapidSigner;
import io.push2u.signer.vault.JdkVaultHttpTransport;
import io.push2u.signer.vault.VaultHttpTransport;
import io.push2u.signer.vault.VaultTransitVapidSigner;

/**
 * Autoconfigures a {@link VaultTransitVapidSigner} as the {@link VapidSigner} from {@code push2u.signer.vault.*}.
 * Active when {@code address}, {@code key-name} and {@code token} are set; {@code public-key} is optional — when
 * omitted (or blank) the signer reads its public key and key version from {@code transit/keys/<key>} at startup and
 * pins that version for signing (the recommended single-source-of-truth mode; the token then needs {@code read} on the
 * key), and when supplied the signer uses it verbatim (token needs only {@code sign}). With an explicit
 * {@code public-key}, set {@code key-version} to pin the matching Transit key version — without it Vault signs with the
 * latest version, which stops matching the configured public key after a key rotation.
 *
 * <p>Ordered before the core starter's {@code Push2uAutoConfiguration} (by name, so this module need not depend on it)
 * and {@link ConditionalOnMissingBean}: when both starters are present this remote signer wins over the in-JVM local
 * signer, while an application-supplied {@link VapidSigner} still overrides both.
 *
 * <p><b>Transport.</b> Every Vault call (the Transit {@code sign} POST and the fetched mode's startup metadata GET)
 * goes through one {@link VaultHttpTransport}, resolved in priority order:
 *
 * <ol>
 *   <li>an application {@link VaultHttpTransport} bean — full control (custom HTTP stack, observability); the
 *       {@code request-timeout}/{@code connect-timeout}/{@code max-response-bytes} properties are then ignored, the
 *       bean owns those concerns;
 *   <li>an application {@link HttpClient} bean qualified {@code "push2uVaultHttpClient"} — the middle road for
 *       mTLS/proxy setups: the starter wraps it in a {@link JdkVaultHttpTransport} with the configured
 *       {@code request-timeout} and {@code max-response-bytes} ({@code connect-timeout} is ignored, the supplied client
 *       owns it);
 *   <li>otherwise a {@link JdkVaultHttpTransport} built entirely from the properties.
 * </ol>
 *
 * The qualifier keeps the Vault client separate from any push-delivery {@code HttpClient} the application may define —
 * the two transports face different trust domains on purpose.
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
     * The Vault Transit signer, built from {@code push2u.signer.vault.*}. Absent unless the address, key name and token
     * are all set, and yields to an application-supplied signer.
     *
     * @param properties the bound configuration
     * @param transport an optional application {@link VaultHttpTransport} for the Vault calls
     * @param vaultHttpClient an optional {@code "push2uVaultHttpClient"}-qualified {@link HttpClient} the default
     *     transport wraps when no transport bean exists
     * @return the signer
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(
            prefix = "push2u.signer.vault",
            name = {"address", "key-name", "token"})
    VapidSigner vaultTransitVapidSigner(
            VaultSignerProperties properties,
            ObjectProvider<VaultHttpTransport> transport,
            @Qualifier("push2uVaultHttpClient") ObjectProvider<HttpClient> vaultHttpClient) {
        VaultHttpTransport resolved = resolveTransport(properties, transport, vaultHttpClient);
        String publicKey = properties.publicKey();
        Integer keyVersion = properties.keyVersion();
        if (publicKey == null || publicKey.isBlank()) {
            if (keyVersion != null) {
                throw new IllegalStateException(
                        "push2u.signer.vault.key-version requires push2u.signer.vault.public-key: in the"
                                + " fetched mode the signer pins the key version it reads from Vault itself");
            }
            // Fetched mode: the signer reads the public key + key version from transit/keys/<key> at
            // construction and pins that version, keeping the Transit key the single source of truth
            // (the token needs `read` on the key).
            return new VaultTransitVapidSigner(
                    properties.address(), properties.mount(), properties.keyName(), properties.token(), resolved);
        }
        // Explicit mode: the published public key is supplied; the token needs only `sign`. Without a
        // key-version the sign requests use Vault's latest key version — rotation-unsafe by contract.
        byte[] point = decodePublicKey(publicKey);
        if (keyVersion == null) {
            return new VaultTransitVapidSigner(
                    properties.address(),
                    properties.mount(),
                    properties.keyName(),
                    properties.token(),
                    point,
                    resolved);
        }
        return new VaultTransitVapidSigner(
                properties.address(),
                properties.mount(),
                properties.keyName(),
                properties.token(),
                point,
                keyVersion,
                resolved);
    }

    /**
     * The configured public key, decoded from base64url. {@link Base64}'s own message names neither the property nor
     * the expected encoding, and a context failure that only says "Illegal base64 character" leaves the operator
     * guessing which of the {@code push2u.*} values is at fault.
     */
    private static byte[] decodePublicKey(String publicKey) {
        try {
            return Base64.getUrlDecoder().decode(publicKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "push2u.signer.vault.public-key is not base64url: expected the 65-byte uncompressed"
                            + " P-256 point as base64url (RFC 4648 §5)",
                    e);
        }
    }

    /** Transport priority: {@code VaultHttpTransport} bean > qualified {@code HttpClient} > defaults. */
    private static VaultHttpTransport resolveTransport(
            VaultSignerProperties properties,
            ObjectProvider<VaultHttpTransport> transport,
            ObjectProvider<HttpClient> vaultHttpClient) {
        VaultHttpTransport supplied = transport.getIfAvailable();
        if (supplied != null) {
            return supplied;
        }
        HttpClient client = vaultHttpClient.getIfAvailable();
        if (client == null) {
            client = HttpClient.newBuilder()
                    .connectTimeout(properties.connectTimeout())
                    .build();
        }
        return new JdkVaultHttpTransport(client, properties.requestTimeout(), properties.maxResponseBytes());
    }
}
