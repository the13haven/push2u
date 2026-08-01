package io.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.push2u.PushHttpClient;
import io.push2u.PushResponse;
import io.push2u.PushSender;
import io.push2u.VapidSigner;
import io.push2u.signer.vault.VaultTransitVapidSigner;
import io.push2u.spring.Push2uAutoConfiguration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link VaultSignerAutoConfiguration} wires a {@link VaultTransitVapidSigner} from
 * {@code push2u.signer.vault.*}, outranks the core starter's local signer, and yields to an
 * application-supplied signer.
 */
class VaultSignerAutoConfigurationTest {

    private static String publicKeyB64;
    private static String privateKeyB64;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(VaultSignerAutoConfiguration.class));

    @BeforeAll
    static void generateVapidKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        publicKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) keyPair.getPublic()));
        privateKeyB64 = base64Url.encodeToString(toFixed32(((ECPrivateKey) keyPair.getPrivate()).getS()));
    }

    @Test
    void wiresTheVaultSignerFromProperties() {
        vaultRunner().run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
        });
    }

    @Test
    void absentWithoutProperties() {
        runner.run(context -> assertThat(context).doesNotHaveBean(VapidSigner.class));
    }

    @Test
    void publicKeyIsOptional_entersFetchedModeWithoutIt() {
        // With address/key-name/token but no public-key, the (relaxed) condition matches and the
        // signer is built in fetched mode — which reads the public key from Vault at construction.
        // Vault is unreachable here, so context startup fails on that fetch (contrast
        // absentWithoutProperties, which wires no bean and starts cleanly). The successful fetch is
        // covered by VaultTransitVapidSignerContractTest.
        runner.withPropertyValues(
                "push2u.signer.vault.address=http://vault.invalid:8200",
                "push2u.signer.vault.key-name=vapid",
                "push2u.signer.vault.token=test-token")
            .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void keyVersionPinsTheExplicitSigner() {
        // Observe the actual sign request through a recording transport: the wired signer must
        // send the configured key_version to Vault. A bean-type assertion alone would stay green
        // even if the wiring dropped the version.
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        vaultRunner()
            .withPropertyValues("push2u.signer.vault.key-version=3")
            .withUserConfiguration(RecordingTransportConfiguration.class)
            .run(context -> {
                assertThat(context).hasSingleBean(VapidSigner.class);
                byte[] signature = context.getBean(VapidSigner.class)
                    .sign("starter key-version probe".getBytes(StandardCharsets.UTF_8));
                assertThat(signature).as("decoded raw r||s signature from the stub response").hasSize(64);
                assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES)
                    .singleElement().asString()
                    .contains("\"key_version\":3");
            });
    }

    @Test
    void withoutKeyVersionTheExplicitSignerSendsNoPin() {
        // The compatibility form: explicit public-key without key-version keeps the historical
        // request shape (Vault signs with its latest version).
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        vaultRunner()
            .withUserConfiguration(RecordingTransportConfiguration.class)
            .run(context -> {
                context.getBean(VapidSigner.class)
                    .sign("starter no-pin probe".getBytes(StandardCharsets.UTF_8));
                assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES)
                    .singleElement().asString()
                    .doesNotContain("key_version");
            });
    }

    @Test
    void keyVersionWithoutPublicKeyFailsLoudly() {
        // key-version only makes sense with an explicit public-key: the fetched mode pins the
        // version it reads from Vault itself. A stray key-version must fail startup, not be
        // silently ignored.
        runner.withPropertyValues(
                "push2u.signer.vault.address=http://vault.invalid:8200",
                "push2u.signer.vault.key-name=vapid",
                "push2u.signer.vault.token=test-token",
                "push2u.signer.vault.key-version=2")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("key-version requires push2u.signer.vault.public-key");
            });
    }

    @Test
    void anApplicationSignerOverridesTheVaultOne() {
        vaultRunner().withUserConfiguration(CustomSignerConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isSameAs(CustomSignerConfiguration.SIGNER);
        });
    }

    @Test
    void theVaultSignerOutranksTheCoreLocalSigner() {
        new ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(VaultSignerAutoConfiguration.class, Push2uAutoConfiguration.class))
            .withPropertyValues(
                "push2u.vapid.public-key=" + publicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64,
                "push2u.vapid.subject=mailto:admin@example.com",
                "push2u.signer.vault.address=http://vault.example:8200",
                "push2u.signer.vault.key-name=vapid",
                "push2u.signer.vault.token=test-token",
                "push2u.signer.vault.public-key=" + publicKeyB64)
            .run(context -> {
                assertThat(context).hasSingleBean(VapidSigner.class);
                assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
                assertThat(context).hasSingleBean(PushSender.class);
            });
    }

    private ApplicationContextRunner vaultRunner() {
        return runner.withPropertyValues(
            "push2u.signer.vault.address=http://vault.example:8200",
            "push2u.signer.vault.key-name=vapid",
            "push2u.signer.vault.token=test-token",
            "push2u.signer.vault.public-key=" + publicKeyB64);
    }

    /**
     * A {@link PushHttpClient} stub the autoconfigured signer picks up (it reuses an application
     * transport bean when present): records every sign request body and answers like Vault's
     * Transit sign endpoint, so tests can assert what was actually sent.
     */
    @Configuration(proxyBeanMethods = false)
    static class RecordingTransportConfiguration {

        static final List<String> SIGN_REQUEST_BODIES = new ArrayList<>();

        @Bean
        PushHttpClient recordingTransport() {
            return (endpoint, headers, body) -> {
                SIGN_REQUEST_BODIES.add(new String(body, StandardCharsets.UTF_8));
                String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
                return new PushResponse(200, Map.of(),
                    "{\"data\":{\"signature\":\"vault:v3:" + signature + "\"}}");
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomSignerConfiguration {

        static final VapidSigner SIGNER = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return new byte[64];
            }

            @Override
            public byte[] publicKey() {
                byte[] key = new byte[65];
                key[0] = 0x04;
                return key;
            }
        };

        @Bean
        VapidSigner applicationSigner() {
            return SIGNER;
        }
    }

    private static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
