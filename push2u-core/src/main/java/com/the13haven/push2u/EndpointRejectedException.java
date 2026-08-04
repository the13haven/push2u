package com.the13haven.push2u;

/**
 * Thrown when the configured {@link EndpointPolicy} refuses a subscription's push endpoint. A dedicated type so that an
 * application iterating a subscription store can tell the outcomes apart: this exception means "this stored
 * subscription violates the deployment's endpoint policy — flag or remove it", where {@link PushDeliveryException}
 * means a transport failure worth retrying and a plain {@link IllegalArgumentException} from {@link PushSender#send}
 * means a message-shaped precondition failure (an oversized payload). It extends {@code IllegalArgumentException}
 * because a policy violation <em>is</em> a precondition failure on the subscription argument, so existing handlers
 * written against the sender's precondition contract keep working unchanged.
 *
 * <p>There is deliberately no cause-taking constructor: the parse and validation exceptions a policy might be tempted
 * to wrap ({@code URISyntaxException} above all) carry the raw endpoint in their message, and a push endpoint is a
 * capability URL that must never travel inside an exception (RFC 8030 §8.3; see {@link Endpoints#redact}).
 */
public class EndpointRejectedException extends IllegalArgumentException {

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
