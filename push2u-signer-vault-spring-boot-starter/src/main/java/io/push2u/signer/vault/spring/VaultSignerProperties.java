package io.push2u.signer.vault.spring;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds {@code push2u.signer.vault.*} for the Vault Transit signer starter.
 *
 * @param address   the Vault base address, e.g. {@code https://vault.example:8200}
 * @param mount     the Transit mount path (default {@code transit})
 * @param keyName   the {@code ecdsa-p256} Transit key name
 * @param token     the Vault token authorising {@code sign} on the key (plus {@code read} on
 *                  {@code transit/keys/<key>} when {@code publicKey} is omitted)
 * @param publicKey the VAPID public key as base64url (the 65-byte uncompressed P-256 point);
 *                  <b>optional</b> — when null/blank the signer reads it from Vault at startup
 */
@ConfigurationProperties("push2u.signer.vault")
public record VaultSignerProperties(URI address, @DefaultValue("transit") String mount, String keyName,
                                    String token, String publicKey) {
}
