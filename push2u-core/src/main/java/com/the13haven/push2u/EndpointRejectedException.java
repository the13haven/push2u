package com.the13haven.push2u;

/**
 * Thrown when the configured {@link EndpointPolicy} refuses a subscription's push endpoint. A dedicated type so that an
 * application iterating a subscription store can tell the outcomes apart: this exception means "this stored
 * subscription violates the deployment's endpoint policy — flag or remove it", where {@link PushDeliveryException}
 * means a transport failure worth retrying and an {@link IllegalArgumentException} from {@link PushSender#send} means a
 * malformed argument (an oversized payload).
 *
 * <p>It extends {@code RuntimeException} directly — like every exception this library owns — and deliberately
 * <em>not</em> {@code IllegalArgumentException}. The rejected argument is well-formed; what refuses it is deployment
 * configuration, and nothing the caller can do to the argument fixes that, so the IAE contract ("your argument is
 * broken") would misdirect the remediation. Just as important, web frameworks routinely map
 * {@code IllegalArgumentException} to an HTTP 400 whose body carries {@code getMessage()} — which would echo the
 * refused origin and the stable subscription fingerprint straight back to the caller who registered the hostile
 * subscription. Rejections only exist where a policy was explicitly configured, so no pre-existing handler depends on
 * any other shape: the deployment that opts in is exactly the one that should decide what a rejection means for its
 * subscription store.
 *
 * <p>There is deliberately no cause-taking constructor: the parse and validation exceptions a policy might be tempted
 * to wrap ({@code URISyntaxException} above all) carry the raw endpoint in their message, and a push endpoint is a
 * capability URL that must never travel inside an exception (RFC 8030 §8.3; see {@link Endpoints#redact}).
 */
public class EndpointRejectedException extends RuntimeException {

    /**
     * Creates an exception describing the rejection. The message must not contain the raw endpoint — render it with
     * {@link Endpoints#redact}.
     *
     * @param message the detail message
     */
    public EndpointRejectedException(String message) {
        super(message);
    }
}
