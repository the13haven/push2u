package io.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.push2u.LocalEcVapidSigner;
import io.push2u.PushSender;
import io.push2u.VapidSigner;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link Push2uAutoConfiguration} wires a {@link PushSender} (and an Actuator health indicator)
 * from {@code push2u.*} properties, backing off to application-supplied beans (ROADMAP phase 5).
 */
class Push2uAutoConfigurationTest {

    private static String publicKeyB64;
    private static String privateKeyB64;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(Push2uAutoConfiguration.class, Push2uHealthAutoConfiguration.class));

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
    void wiresPushSenderFromProperties() {
        keyedRunner().run(context -> {
            assertThat(context).hasSingleBean(PushSender.class);
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isInstanceOf(LocalEcVapidSigner.class);
        });
    }

    @Test
    void withoutKeysThereIsNoSenderOrSigner() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(PushSender.class);
            assertThat(context).doesNotHaveBean(VapidSigner.class);
        });
    }

    @Test
    void anApplicationSignerOverridesTheLocalOne() {
        keyedRunner().withUserConfiguration(CustomSignerConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isSameAs(CustomSignerConfiguration.SIGNER);
            assertThat(context).hasSingleBean(PushSender.class);
        });
    }

    @Test
    void healthIndicatorReportsUpWithTheSignerType() {
        keyedRunner().run(context -> {
            assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.UP);
            assertThat(health.getDetails()).containsEntry("signer", "LocalEcVapidSigner");
        });
    }

    @Test
    void healthIndicatorReportsDownWhenTheSignerFails() {
        keyedRunner().withUserConfiguration(FailingSignerConfiguration.class).run(context -> {
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.DOWN);
            assertThat(health.getDetails()).containsKey("error");
        });
    }

    private ApplicationContextRunner keyedRunner() {
        return runner.withPropertyValues(
            "push2u.vapid.public-key=" + publicKeyB64,
            "push2u.vapid.private-key=" + privateKeyB64,
            "push2u.vapid.subject=mailto:admin@example.com");
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

    @Configuration(proxyBeanMethods = false)
    static class FailingSignerConfiguration {

        @Bean
        VapidSigner failingSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    throw new IllegalStateException("signer backend unavailable");
                }

                @Override
                public byte[] publicKey() {
                    byte[] key = new byte[65];
                    key[0] = 0x04;
                    return key;
                }
            };
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
