package io.push2u.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import io.push2u.JdkHttpPushClient;
import io.push2u.LocalEcVapidSigner;
import io.push2u.PushHttpClient;
import io.push2u.PushSender;
import io.push2u.RetryPolicy;
import io.push2u.VapidKeys;
import io.push2u.VapidSigner;

/**
 * Autoconfigures a ready {@link PushSender} from {@code push2u.*} properties: an in-JVM VAPID signer when keys are
 * present, the JDK HTTP transport, and the send facade. Each bean is {@link ConditionalOnMissingBean}, so any of them
 * can be replaced by an application-supplied bean — chiefly a remote {@link VapidSigner} (e.g. Vault Transit). The
 * Actuator health indicator is added by {@link Push2uHealthAutoConfiguration}.
 */
@AutoConfiguration
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uAutoConfiguration {

    Push2uAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The in-JVM VAPID signer, built from {@code push2u.vapid.public-key} / {@code .private-key}. Absent unless both
     * keys are set, and yields to an application-supplied {@link VapidSigner} (so a remote signer wins).
     *
     * @param properties the bound configuration
     * @return the local signer
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(
            prefix = "push2u.vapid",
            name = {"public-key", "private-key"})
    public VapidSigner push2uVapidSigner(Push2uProperties properties) {
        Push2uProperties.Vapid vapid = properties.vapid();
        return new LocalEcVapidSigner(VapidKeys.fromBase64(vapid.publicKey(), vapid.privateKey()));
    }

    /**
     * The HTTP transport; defaults to {@link JdkHttpPushClient}, overridable by an application bean.
     *
     * @return the transport
     */
    @Bean
    @ConditionalOnMissingBean
    public PushHttpClient push2uPushHttpClient() {
        return new JdkHttpPushClient();
    }

    /**
     * The send facade, wired from the {@link VapidSigner} (local or application-supplied), the transport, and the
     * properties. Created only once a signer is available, and only when the application has not supplied its own
     * {@link PushSender} bean — an application-supplied {@code PushSender} bypasses this method entirely, so none of
     * the checks below apply to it.
     *
     * <p>{@code push2u.vapid.subject} is required for this autoconfigured sender even when the signer itself comes from
     * another starter (e.g. the Vault Transit signer starter, which supplies only key custody, not a contact address):
     * it is checked here, with a message naming the property, so a missing subject fails with an actionable diagnostic
     * rather than {@link PushSender.Builder#build()}'s generic {@code "contact is required"}.
     *
     * <p>{@code push2u.record-size} / {@code push2u.max-encrypted-body-bytes} failures from
     * {@link PushSender.Builder#recordSize(int)} / {@link PushSender.Builder#maxEncryptedBodyBytes(int)} are re-thrown
     * with the property name prefixed, since the builder's own message names its camelCase parameter, not the YAML
     * property.
     *
     * @param signer the VAPID signer
     * @param httpClient the HTTP transport
     * @param properties the bound configuration
     * @return the configured sender
     * @throws IllegalStateException if {@code push2u.vapid.subject} is unset or blank
     * @throws IllegalArgumentException if {@code push2u.record-size} or {@code push2u.max-encrypted-body-bytes} is set
     *     to a value the builder rejects
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VapidSigner.class)
    public PushSender pushSender(VapidSigner signer, PushHttpClient httpClient, Push2uProperties properties) {
        String subject = properties.vapid().subject();
        if (subject == null || subject.isBlank()) {
            throw new IllegalStateException(
                    "push2u.vapid.subject is required (the VAPID 'sub' claim: optional in RFC 8292 §2.1,"
                            + " required by push2u). Set it even when the signer itself comes from another"
                            + " starter, e.g. the Vault Transit signer starter, which supplies only key"
                            + " custody, not a contact address");
        }
        Push2uProperties.Retry retry = properties.retry();
        PushSender.Builder builder = PushSender.builder()
                .signer(signer)
                .contact(subject)
                .httpClient(httpClient)
                .retryPolicy(new RetryPolicy(retry.maxAttempts(), retry.initialBackoff(), retry.maxBackoff()));
        if (properties.jwtExpiry() != null) {
            builder.jwtExpiry(properties.jwtExpiry());
        }
        if (properties.defaultTtl() != null) {
            builder.defaultTtl(properties.defaultTtl());
        }
        if (properties.recordSize() != null) {
            try {
                builder.recordSize(properties.recordSize());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("push2u.record-size: " + e.getMessage(), e);
            }
        }
        if (properties.maxEncryptedBodyBytes() != null) {
            try {
                builder.maxEncryptedBodyBytes(properties.maxEncryptedBodyBytes());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("push2u.max-encrypted-body-bytes: " + e.getMessage(), e);
            }
        }
        return builder.build();
    }
}
