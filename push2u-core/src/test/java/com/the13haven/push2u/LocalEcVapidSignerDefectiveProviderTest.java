/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * {@code Signature.sign()} is the provider's own implementation answering, and a defective one can answer {@code null}
 * instead of signature bytes. That answer travels: on a raw-format (P1363) provider it would leave
 * {@link LocalEcVapidSigner#sign} — a published method in a null-marked package — as a silent {@code null} return, and
 * in the construction-time self-test it would be handed back to the provider's {@code verify}, whose
 * {@link NullPointerException} would escape the public constructor. Both call sites must instead refuse it as the
 * library's own {@link PushCryptoException}, which is what these tests pin.
 *
 * <p>The always-null shape can only ever surface at construction — the self-test signs before any send — so reaching
 * {@code sign()} itself takes an <em>intermittently</em> defective provider: one genuine answer for the self-test,
 * {@code null} from then on. The provider is passed by reference through {@code Jca.using(...)}, like the other
 * hostile-provider probes in this suite; everything but {@code engineSign}'s answer is delegated to the platform's
 * SunEC, so the failure under test is the only defect in play.
 */
class LocalEcVapidSignerDefectiveProviderTest {

    private static final byte[] ANY_INPUT =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.e30".getBytes(StandardCharsets.US_ASCII);

    /** The self-test signs first, so a provider that never answers is refused before the signer ever exists. */
    @Test
    void aProviderAnsweringNoSignatureAtAllIsRefusedByTheConstructionTimeSelfTest() {
        Jca defective = Jca.using(new NullSigningProvider(0));

        assertThatThrownBy(() -> new LocalEcVapidSigner(PushTestSupport.generateVapidKeys(), defective))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no signature at all");
    }

    /**
     * The published path: one genuine answer lets the self-test pass, then {@code sign()} gets the {@code null} — and
     * must throw rather than return it, because its contract promises a fresh 64-byte array, never {@code null}.
     */
    @Test
    void aProviderAnsweringNoSignatureAtAllOnSendFailsClosedInsteadOfReturningNull() {
        Jca defective = Jca.using(new NullSigningProvider(1));
        LocalEcVapidSigner signer = new LocalEcVapidSigner(PushTestSupport.generateVapidKeys(), defective);

        assertThatThrownBy(() -> signer.sign(ANY_INPUT))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no signature at all");
    }

    /**
     * A provider registering the raw-format ES256 name with a signature whose {@code sign()} answers genuinely
     * {@code genuineAnswers} times and {@code null} from then on, everything else (the ECDSA math itself, key import,
     * parameters) delegated to the platform's SunEC — so the signer's construction and verification run for real and
     * only the answer under test is defective.
     */
    private static final class NullSigningProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        NullSigningProvider(int genuineAnswers) {
            super("push2u-null-signing", "1.0", "answers ES256 signing with null after N genuine answers");
            AtomicInteger genuineAnswersLeft = new AtomicInteger(genuineAnswers);
            putService(
                    new Service(
                            this,
                            "Signature",
                            Algorithms.ES256_P1363,
                            NullAnsweringSignature.class.getName(),
                            null,
                            null) {
                        @Override
                        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
                            return new NullAnsweringSignature(genuineAnswersLeft);
                        }
                    });
            delegateToSunEc("KeyFactory");
            delegateToSunEc("AlgorithmParameters");
        }

        private void delegateToSunEc(String type) {
            Provider.Service source =
                    java.security.Security.getProvider("SunEC").getService(type, Algorithms.EC);
            putService(new Service(this, type, Algorithms.EC, source.getClassName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
                    return source.newInstance(constructorParameter);
                }
            });
        }
    }

    /** The {@code SignatureSpi} behind {@link NullSigningProvider}: real SunEC ECDSA with a rationed {@code sign()}. */
    public static final class NullAnsweringSignature extends SignatureSpi {

        private final Signature delegate;
        private final AtomicInteger genuineAnswersLeft;

        NullAnsweringSignature(AtomicInteger genuineAnswersLeft) throws NoSuchAlgorithmException {
            this.delegate = Signature.getInstance(Algorithms.ES256_P1363, java.security.Security.getProvider("SunEC"));
            this.genuineAnswersLeft = genuineAnswersLeft;
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            delegate.initSign(privateKey);
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            delegate.initVerify(publicKey);
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            delegate.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            delegate.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            return genuineAnswersLeft.getAndDecrement() > 0 ? delegate.sign() : null;
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return delegate.verify(sigBytes);
        }

        @Override
        protected void engineSetParameter(String param, Object value) {
            throw new UnsupportedOperationException("unused by the signer under test");
        }

        @Override
        protected Object engineGetParameter(String param) {
            throw new UnsupportedOperationException("unused by the signer under test");
        }
    }
}
