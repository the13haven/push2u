package io.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.push2u.PushCryptoException;
import io.push2u.PushSender;
import io.push2u.VapidSigner;
import io.push2u.signer.vault.VaultHttpResponse;
import io.push2u.signer.vault.VaultHttpTransport;
import io.push2u.signer.vault.VaultTransitVapidSigner;
import io.push2u.spring.Push2uAutoConfiguration;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
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
 * application-supplied signer. The transport extension point resolves in priority order:
 * application {@link VaultHttpTransport} bean, then a {@code push2uVaultHttpClient}-qualified
 * {@link HttpClient} wrapped with the bound transport properties, then pure defaults.
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

    @Test
    void aVaultHttpTransportBeanOutranksTheQualifiedHttpClient() {
        // Both extension points present at once: the transport bean must win, and the qualified
        // client must stay untouched — otherwise a user migrating to a full transport would keep
        // silently sending through the leftover client.
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        QualifiedHttpClientConfiguration.CLIENT.sends = 0;
        vaultRunner()
            .withUserConfiguration(RecordingTransportConfiguration.class, QualifiedHttpClientConfiguration.class)
            .run(context -> {
                context.getBean(VapidSigner.class)
                    .sign("starter transport-priority probe".getBytes(StandardCharsets.UTF_8));
                assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES).hasSize(1);
                assertThat(QualifiedHttpClientConfiguration.CLIENT.sends)
                    .as("the qualified HttpClient is bypassed when a transport bean exists")
                    .isZero();
            });
    }

    @Test
    void theQualifiedHttpClientBacksTheDefaultTransport() throws Exception {
        // No VaultHttpTransport bean: the starter must wrap the push2uVaultHttpClient-qualified
        // client — the mTLS/proxy extension point — and route the sign call through it.
        QualifiedHttpClientConfiguration.CLIENT.sends = 0;
        withStubVault(signResponse(), stubAddress ->
            explicitRunner(stubAddress)
                .withUserConfiguration(QualifiedHttpClientConfiguration.class)
                .run(context -> {
                    byte[] signature = context.getBean(VapidSigner.class)
                        .sign("starter qualified-client probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(signature).hasSize(64);
                    assertThat(QualifiedHttpClientConfiguration.CLIENT.sends)
                        .as("the sign request went through the qualified HttpClient")
                        .isEqualTo(1);
                }));
    }

    @Test
    void maxResponseBytesReachesTheBuiltTransport() throws Exception {
        // Bind a deliberately tiny cap and let the stub Vault answer with a normal-size sign
        // response: the call must fail closed with the transport's limit error — proving the
        // property actually shapes the transport instead of being silently dropped.
        withStubVault(signResponse(), stubAddress ->
            explicitRunner(stubAddress)
                .withPropertyValues("push2u.signer.vault.max-response-bytes=16")
                .run(context -> assertThatThrownBy(() -> context.getBean(VapidSigner.class)
                    .sign("starter cap probe".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("exceeded the configured limit of 16 bytes")));
    }

    @Test
    void requestTimeoutReachesTheBuiltTransport() throws Exception {
        // A socket that accepts but never answers: only the bound request-timeout can end the
        // exchange — before this seam existed, the metadata GET could hang startup forever.
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            explicitRunner("http://127.0.0.1:" + silent.getLocalPort())
                .withPropertyValues("push2u.signer.vault.request-timeout=500ms")
                .run(context -> assertThatThrownBy(() -> context.getBean(VapidSigner.class)
                    .sign("starter timeout probe".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("timed out"));
        }
    }

    @Test
    void nonPositiveTransportPropertiesFailStartup() {
        vaultRunner()
            .withPropertyValues("push2u.signer.vault.request-timeout=0s")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("request-timeout must be positive");
            });
        vaultRunner()
            .withPropertyValues("push2u.signer.vault.max-response-bytes=0")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("max-response-bytes must be positive");
            });
        vaultRunner()
            .withPropertyValues("push2u.signer.vault.connect-timeout=-1s")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("connect-timeout must be positive");
            });
    }

    private ApplicationContextRunner vaultRunner() {
        return runner.withPropertyValues(
            "push2u.signer.vault.address=http://vault.example:8200",
            "push2u.signer.vault.key-name=vapid",
            "push2u.signer.vault.token=test-token",
            "push2u.signer.vault.public-key=" + publicKeyB64);
    }

    /** An explicit-mode runner pointed at a live local stub Vault (no transport bean). */
    private ApplicationContextRunner explicitRunner(String address) {
        return runner.withPropertyValues(
            "push2u.signer.vault.address=" + address,
            "push2u.signer.vault.key-name=vapid",
            "push2u.signer.vault.token=test-token",
            "push2u.signer.vault.public-key=" + publicKeyB64);
    }

    /** A well-formed Transit sign response carrying 64 zero bytes as the signature. */
    private static String signResponse() {
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
        return "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}";
    }

    /** Serve {@code responseBody} for every request on an ephemeral port and run {@code test}. */
    private static void withStubVault(String responseBody, StubVaultTest test) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            server.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            test.run("http://127.0.0.1:" + server.getAddress().getPort());
        } finally {
            server.stop(0);
        }
    }

    private interface StubVaultTest {
        void run(String address) throws Exception;
    }

    /**
     * A {@link VaultHttpTransport} stub the autoconfigured signer picks up (an application
     * transport bean outranks every built-in default): records every sign request body and answers
     * like Vault's Transit sign endpoint, so tests can assert what was actually sent.
     */
    @Configuration(proxyBeanMethods = false)
    static class RecordingTransportConfiguration {

        static final List<String> SIGN_REQUEST_BODIES = new ArrayList<>();

        @Bean
        VaultHttpTransport recordingTransport() {
            return new VaultHttpTransport() {
                @Override
                public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    throw new AssertionError("the explicit mode must never read key metadata from Vault");
                }

                @Override
                public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                    SIGN_REQUEST_BODIES.add(new String(body, StandardCharsets.UTF_8));
                    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
                    return new VaultHttpResponse(200,
                        "{\"data\":{\"signature\":\"vault:v3:" + signature + "\"}}");
                }
            };
        }
    }

    /** The mTLS/proxy extension point: an {@link HttpClient} qualified {@code push2uVaultHttpClient}. */
    @Configuration(proxyBeanMethods = false)
    static class QualifiedHttpClientConfiguration {

        static final RecordingHttpClient CLIENT = new RecordingHttpClient(HttpClient.newHttpClient());

        @Bean("push2uVaultHttpClient")
        HttpClient push2uVaultHttpClient() {
            return CLIENT;
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
