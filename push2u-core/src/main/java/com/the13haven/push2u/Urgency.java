package com.the13haven.push2u;

/**
 * Message urgency (RFC 8030 §5.3), sent as the {@code Urgency} header so a push service can decide whether to deliver
 * to a battery-constrained device immediately. The {@link #headerValue()} is the on-the-wire token.
 */
public enum Urgency {

    /** Lowest — e.g. advertisements; deliver only when the device is on power and Wi-Fi. */
    VERY_LOW("very-low"),
    /** Low — e.g. topic updates; deliver when on power or Wi-Fi. */
    LOW("low"),
    /** Default priority — e.g. chat or calendar messages. */
    NORMAL("normal"),
    /** Highest — e.g. an incoming call or time-sensitive alert; deliver regardless of device state. */
    HIGH("high");

    private final String headerValue;

    Urgency(String headerValue) {
        this.headerValue = headerValue;
    }

    /**
     * The on-the-wire {@code Urgency} header token (e.g. {@code "very-low"}).
     *
     * @return the header token
     */
    public String headerValue() {
        return headerValue;
    }
}
