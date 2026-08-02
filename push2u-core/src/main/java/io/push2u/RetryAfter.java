package io.push2u;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for the {@code Retry-After} response header (RFC 9110 §10.2.3): either delta-seconds
 * ({@code 1*DIGIT}) or an HTTP-date in any of the three formats recipients are required to
 * accept (RFC 9110 §5.6.7):
 *
 * <ul>
 *   <li>IMF-fixdate — {@code Sun, 06 Nov 1994 08:49:37 GMT};</li>
 *   <li>obsolete RFC 850 — {@code Sunday, 06-Nov-94 08:49:37 GMT}, its two-digit year read per
 *       the RFC 9110 §5.6.7 recipient rule: a timestamp that would appear more than 50 years in
 *       the future is read as the most recent year in the past with the same last two digits.
 *       The rule is about the full timestamp, not the year number: a header whose year number
 *       is exactly 50 ahead still rolls back a century when its month and day land past
 *       "now" plus 50 calendar years;</li>
 *   <li>obsolete asctime — {@code Sun Nov  6 08:49:37 1994}, which carries no zone and is
 *       interpreted as UTC.</li>
 * </ul>
 *
 * <p>A seconds value of {@code 60} — a leap second, which the HTTP-date grammar permits but
 * java.time formatters reject — is accepted in all three formats and resolves to the instant
 * one second past the corresponding {@code :59}. The two-digit-year rule above judges that
 * final, incremented instant: a {@code :60} whose increment carries the timestamp past the
 * 50-year boundary rolls back a century just as a plain second past it would.
 *
 * <p>All formatters are locale-independent ({@link Locale#ROOT}). A value matching none of the
 * forms — including delta-seconds too large for a {@code long} — yields
 * {@link Optional#empty()}, never an exception, so a malformed header degrades to the caller's
 * computed backoff instead of failing the send.
 *
 * <p>Parsing uses java.time's default {@code SMART} resolver, so a day-of-month that does not
 * exist in the resolved year — {@code 29-Feb} of a non-leap year — is pulled back to the 28th
 * rather than rejected. The header was malformed either way and the effect is bounded to one
 * day, so it is left as the JDK behaves rather than papered over.
 */
final class RetryAfter {

    /** asctime date: space-padded day-of-month, no zone (UTC by convention). */
    static final DateTimeFormatter ASCTIME_DATE =
        DateTimeFormatter.ofPattern("EEE MMM ppd HH:mm:ss yyyy", Locale.ROOT);

    /**
     * A leap second: a {@code 60} in the seconds position of an {@code HH:MM:SS} time-of-day.
     * Anchored on the two preceding colon-separated pairs so a {@code 60} elsewhere (a year, a
     * day) never matches; the lookahead keeps a third digit from posing as a seconds field.
     */
    private static final Pattern LEAP_SECOND = Pattern.compile("(\\d{2}:\\d{2}):60(?!\\d)");

    /**
     * Memoised pair of RFC 850 formatters, keyed on the year of "now". Both century windows a
     * parse may need — recent and previous — live in one record: a single-formatter entry
     * keyed on the base year would thrash whenever the two windows alternate, rebuilding a
     * formatter on every other call. The windows follow "now", so the formatters cannot be
     * static constants; rebuilding them on every parse would be wasteful, hence the same
     * memoisation shape {@link Jca} uses for its ES256 resolution: a volatile field holding an
     * immutable record, recomputed idempotently when stale — a benign race at worst rebuilds
     * an equal pair and both writers store an equivalent value. The key changes once a year,
     * so in steady state this is a single volatile read.
     */
    private static volatile Rfc850 rfc850;

    /**
     * The two RFC 850 century windows valid for a given "now" year: {@code recentCentury}
     * resolves two-digit years within {@code [nowYear - 49, nowYear + 50]},
     * {@code previousCentury} within {@code [nowYear - 149, nowYear - 50]} — each two-digit
     * year has exactly one reading in each, a hundred years apart.
     */
    record Rfc850(int nowYear, DateTimeFormatter recentCentury, DateTimeFormatter previousCentury) {
    }

    private RetryAfter() {
    }

    /**
     * Builds an RFC 850 date formatter: full weekday name, two-digit year read in the
     * {@code [baseYear, baseYear + 99]} window. The weekday names are an explicit map because
     * {@link Locale#ROOT} carries no full-name day text (an {@code EEEE} pattern would only
     * match the abbreviated form).
     *
     * <p>Package-private, not private: the locale binding is asserted directly by the tests. A
     * behavioural test alone cannot pin it — the formatters a parse call uses are memoised, so
     * whether a given parse constructs one (under whatever default locale that test set)
     * depends on what ran before; the direct assertion is order-independent.
     */
    static DateTimeFormatter rfc850Date(int baseYear) {
        return new DateTimeFormatterBuilder()
            .appendText(ChronoField.DAY_OF_WEEK, Map.of(
                1L, "Monday", 2L, "Tuesday", 3L, "Wednesday", 4L, "Thursday",
                5L, "Friday", 6L, "Saturday", 7L, "Sunday"))
            .appendPattern(", dd-MMM-")
            .appendValueReduced(ChronoField.YEAR, 2, 2, baseYear)
            .appendPattern(" HH:mm:ss zzz")
            .toFormatter(Locale.ROOT);
    }

    /**
     * The memoised formatter pair for a "now" year — see {@link #rfc850}. Package-private so
     * the tests can assert the memo hands back the same instances rather than rebuilding.
     */
    static Rfc850 rfc850Formatters(int nowYear) {
        Rfc850 memo = rfc850;
        if (memo == null || memo.nowYear() != nowYear) {
            memo = new Rfc850(nowYear, rfc850Date(nowYear - 49), rfc850Date(nowYear - 149));
            rfc850 = memo;
        }
        return memo;
    }

    /**
     * Parses a {@code Retry-After} value against a fixed "now".
     *
     * <p>A date at or before {@code now} — which clock skew or in-flight latency can produce —
     * yields {@link Duration#ZERO}, i.e. retry immediately. That is what the header says, so it
     * is honoured rather than quietly floored at the caller's backoff: the retry count already
     * bounds how often it can happen.
     *
     * @param headerValue the raw header value (surrounding whitespace is ignored)
     * @param now         the instant HTTP-date forms are measured against
     * @return the delay to wait — {@link Duration#ZERO} for a date at or before {@code now} —
     *         or empty when the value matches none of the supported forms
     */
    static Optional<Duration> parse(String headerValue, Instant now) {
        String value = headerValue.trim();
        if (value.isEmpty()) {
            return Optional.empty();
        }
        if (isAsciiDigits(value)) {
            return parseDeltaSeconds(value);
        }
        return parseHttpDate(value, now).map(date -> untilAtLeastZero(now, date));
    }

    /** Delta-seconds is {@code 1*DIGIT} — ASCII only; {@code Character.isDigit} would also let
     * non-ASCII digits through, which is outside the grammar. */
    private static boolean isAsciiDigits(String value) {
        return value.chars().allMatch(c -> c >= '0' && c <= '9');
    }

    private static Optional<Duration> parseDeltaSeconds(String value) {
        try {
            return Optional.of(Duration.ofSeconds(Long.parseLong(value)));
        } catch (NumberFormatException overflow) {
            // All-digit but larger than a long: syntactically delta-seconds, practically
            // unusable — treat the header as unparseable rather than propagate.
            return Optional.empty();
        }
    }

    /**
     * HTTP-date permits a seconds value of 60 (a leap second); java.time formatters accept only
     * 0..59. Substitute {@code :59} once and hand the one-second step down to
     * {@link #parseTimestamp} as {@code leapSecondAdjustment}, applied by each parse the moment
     * it succeeds. The adjustment is threaded down rather than applied here on the returned
     * instant because the RFC 850 century decision compares the timestamp against "now" plus 50
     * years: an increment applied after that comparison would let it judge an instant one second
     * earlier than the one the caller receives, flipping the century at the exact boundary.
     *
     * <p>What keeps this bounded is that the substituted value goes to {@link #parseTimestamp},
     * not back through this method: normalising one group at a time and re-entering here would
     * recurse once per {@code HH:MM:60} group and re-scan the whole value each time — quadratic,
     * and a header of a few tens of kilobytes (the remote push service chooses its size) would
     * exhaust the stack and throw out of a class whose contract is to never throw.
     *
     * <p>Substituting only the first match loses nothing: a valid HTTP-date has a single
     * time-of-day, so a value carrying a second group is malformed and must fail the formatters
     * either way.
     */
    private static Optional<Instant> parseHttpDate(String value, Instant now) {
        Matcher leapSecond = LEAP_SECOND.matcher(value);
        if (leapSecond.find()) {
            return parseTimestamp(leapSecond.replaceFirst("$1:59"), now, 1);
        }
        return parseTimestamp(value, now, 0);
    }

    /**
     * The three HTTP-date forms, tried in order. {@code leapSecondAdjustment} is the seconds to
     * add to a successfully parsed instant (1 when the caller substituted a leap second's
     * {@code :60} with {@code :59}, else 0); each branch applies it immediately so every
     * consumer — including the RFC 850 century gate — sees the final instant.
     */
    private static Optional<Instant> parseTimestamp(String value, Instant now, long leapSecondAdjustment) {
        try {
            return Optional.of(ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                .toInstant().plusSeconds(leapSecondAdjustment));
        } catch (DateTimeParseException notImfFixdate) {
            // Fall through to the obsolete forms.
        }
        Optional<Instant> obsoleteForm = parseRfc850(value, now, leapSecondAdjustment);
        if (obsoleteForm.isPresent()) {
            return obsoleteForm;
        }
        try {
            return Optional.of(LocalDateTime.parse(value, ASCTIME_DATE).toInstant(ZoneOffset.UTC)
                .plusSeconds(leapSecondAdjustment));
        } catch (DateTimeParseException notAsctime) {
            return Optional.empty();
        }
    }

    /**
     * RFC 850 form, its two-digit year resolved per RFC 9110 §5.6.7: a timestamp that would
     * appear more than 50 years in the future MUST be read as the most recent past year with
     * the same last two digits. The rule is about the full timestamp, so the year alone cannot
     * decide it: a two-digit year has a recent-century reading within
     * {@code [nowYear - 49, nowYear + 50]} and a previous-century reading a hundred years
     * earlier, and the recent one stands only while its month, day and time keep it at or
     * before "now" plus 50 calendar years — strictly beyond that, the previous century is
     * meant.
     *
     * <p>Two parse attempts, not one parse shifted a century: the formatter cross-checks the
     * stated weekday during resolution, and a date is never on the same weekday a hundred
     * years apart (the shift is 36524 or 36525 days, neither divisible by 7), so a header
     * carrying the previous-century weekday fails the recent-century parse outright — there
     * is no parsed value to shift. The cross-check is kept deliberately: a header whose
     * weekday matches neither candidate, or only the candidate the rule rejects, is
     * contradictory and yields empty rather than a timestamp the sender cannot have meant.
     *
     * <p>The 50-year comparison is made on the leap-second-adjusted instant — the one the
     * caller will receive. Judging the pre-adjustment instant would read a {@code :60} landing
     * exactly one second past the boundary as still within it, keeping the recent century for
     * a timestamp whose final value is more than 50 years ahead.
     *
     * <p>Two deliberate limits. The adjustment on the previous-century return value cannot be
     * observed through the public API — that window is at least 49 years past, so the caller
     * floors it to zero either way; it is applied for consistency, not for an effect any test
     * could defend. And shifting the previous-century reading by 100 years to test it against
     * the horizon diverges from the true recent-century reading when only one of the two years
     * is a leap year and the date is 29 February — reachable only with a clock set roughly 50
     * years before a century year, so it is left alone rather than paid for.
     */
    private static Optional<Instant> parseRfc850(String value, Instant now, long leapSecondAdjustment) {
        Rfc850 formatters = rfc850Formatters(now.atOffset(ZoneOffset.UTC).getYear());
        // Calendar arithmetic, not a fixed second count: "50 years ahead" follows the calendar.
        Instant latestRecent = now.atOffset(ZoneOffset.UTC).plusYears(50).toInstant();
        try {
            Instant recent = ZonedDateTime.parse(value, formatters.recentCentury()).toInstant()
                .plusSeconds(leapSecondAdjustment);
            if (!recent.isAfter(latestRecent)) {
                return Optional.of(recent);
            }
            // Parsed, but more than 50 years ahead: the rule prescribes the previous century,
            // whose weekday is necessarily different — the attempt below fails, and rightly:
            // this header is only self-consistent in the century the rule rejects.
        } catch (DateTimeParseException notTheRecentCentury) {
            // The stated weekday may belong to the previous-century reading instead.
        }
        try {
            ZonedDateTime previous = ZonedDateTime.parse(value, formatters.previousCentury());
            if (previous.plusYears(100).toInstant().plusSeconds(leapSecondAdjustment).isAfter(latestRecent)) {
                return Optional.of(previous.toInstant().plusSeconds(leapSecondAdjustment));
            }
            // The recent-century reading is within 50 years, so the rule keeps it; a weekday
            // matching only the previous century contradicts it.
            return Optional.empty();
        } catch (DateTimeParseException notRfc850) {
            return Optional.empty();
        }
    }

    private static Duration untilAtLeastZero(Instant now, Instant date) {
        Duration delay = Duration.between(now, date);
        return delay.isNegative() ? Duration.ZERO : delay;
    }
}
