package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class RetryPolicyTest {

    @Test
    void exponentialBackoffDoublesAndCapsAtMax() {
        RetryPolicy policy = new RetryPolicy(10, Duration.ofSeconds(1), Duration.ofSeconds(10));
        assertThat(policy.backoffFor(1)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(2)).isEqualTo(Duration.ofSeconds(2));
        assertThat(policy.backoffFor(3)).isEqualTo(Duration.ofSeconds(4));
        assertThat(policy.backoffFor(4)).isEqualTo(Duration.ofSeconds(8));
        assertThat(policy.backoffFor(5)).as("16s capped to maxBackoff").isEqualTo(Duration.ofSeconds(10));
        assertThat(policy.backoffFor(40)).as("no overflow, still capped").isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void defaultsAndNoneArePlausible() {
        assertThat(RetryPolicy.defaults().maxAttempts()).isEqualTo(3);
        assertThat(RetryPolicy.none().maxAttempts()).isEqualTo(1);
    }

    @Test
    void rejectsInvalidConfiguration() {
        assertThatThrownBy(() -> new RetryPolicy(0, Duration.ZERO, Duration.ZERO))
            .isInstanceOf(IllegalArgumentException.class);

        Duration negativeBackoff = Duration.ofSeconds(-1);
        assertThatThrownBy(() -> new RetryPolicy(1, negativeBackoff, Duration.ZERO))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
