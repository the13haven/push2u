/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

import org.junit.jupiter.api.Test;

/**
 * Format matrix for the {@code Retry-After} parser: delta-seconds plus the three HTTP-date forms (IMF-fixdate, RFC 850,
 * asctime) against a pinned "now" (2022-11-06 was a Sunday, so the day-of-week in every date vector is consistent), the
 * RFC 9110 §5.6.7 two-digit-year rule, and leap-second handling. Malformed values must yield empty — never an
 * exception.
 *
 * <p>Every weekday in the date vectors was verified against java.time's calendar for the year the vector is expected to
 * resolve to — a wrong weekday fails the formatter's cross-check and would test nothing but the vector's own typo.
 */
class RetryAfterTest {

    private static final Instant NOW = Instant.parse("2022-11-06T08:49:00Z");

    /** A "now" in 2026, giving the RFC 850 two-digit-year window [1977, 2076]. */
    private static final Instant NOW_2026 = Instant.parse("2026-08-01T00:00:00Z");

    @Test
    void parsesDeltaSeconds() {
        assertThat(RetryAfter.parse("120", NOW)).contains(Duration.ofSeconds(120));
    }

    @Test
    void parsesImfFixdate() {
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:37 GMT", NOW)).contains(Duration.ofSeconds(37));
    }

    @Test
    void parsesRfc850DateWithTwoDigitYearInTheCurrentCentury() {
        assertThat(RetryAfter.parse("Sunday, 06-Nov-22 08:49:37 GMT", NOW)).contains(Duration.ofSeconds(37));
    }

    @Test
    void rfc850TwoDigitYearFarInThePastResolvesToThePastCentury() {
        // RFC 9110 §5.6.7's own RFC 850 example: with "now" in 2026, "94" MUST mean 1994 (the
        // most recent past year ending in 94), not 2094 — 1994-11-06 was a Sunday, so the value
        // parses and, being in the past, yields ZERO. A century pinned at 2000 read it as 2094,
        // a Saturday, and the weekday cross-check discarded the whole header as unparseable.
        assertThat(RetryAfter.parse("Sunday, 06-Nov-94 08:49:37 GMT", NOW_2026)).contains(Duration.ZERO);
    }

    @Test
    void rfc850TimestampExactlyFiftyYearsAheadStaysInTheRecentCentury() {
        // The 50-year rule is strict — "more than 50 years in the future" — and it is about
        // the full timestamp, not the year number. Exactly "now" plus 50 calendar years
        // (2076-08-01T00:00:00, a Saturday) is not beyond the limit, so it stays 2076.
        assertThat(RetryAfter.parse("Saturday, 01-Aug-76 00:00:00 GMT", NOW_2026))
                .contains(Duration.between(NOW_2026, Instant.parse("2076-08-01T00:00:00Z")));
    }

    @Test
    void rfc850TimestampOneSecondPastFiftyYearsRollsBackACentury() {
        // One second past "now" plus 50 calendar years is "more than 50 years in the future",
        // so the same two-digit year now means 1976 — whose Aug 1 was a Sunday. The past date
        // yields ZERO; empty would mean the century (and weekday) came out wrong.
        assertThat(RetryAfter.parse("Sunday, 01-Aug-76 00:00:01 GMT", NOW_2026)).contains(Duration.ZERO);
    }

    @Test
    void rfc850YearNumberAtTheBoundaryStillRollsBackWhenTheTimestampIsBeyond() {
        // "76" is exactly nowYear + 50 by year number, but 2076-11-06 is 50 years and roughly
        // three months after 2026-08-01 — more than 50 years — so the header means 1976, a
        // Saturday, in the past, hence ZERO. A year-granular window kept 2076 (a Friday) and
        // rejected this correct header on the weekday cross-check.
        assertThat(RetryAfter.parse("Saturday, 06-Nov-76 08:49:37 GMT", NOW_2026))
                .contains(Duration.ZERO);
    }

    @Test
    void rfc850WeekdayOfTheRejectedCenturyIsContradictoryNotADecadesLongDelay() {
        // Friday is 2076-11-06's weekday, but the rule reads this timestamp as 1976 (a
        // Saturday): a header self-consistent only in the century the rule rejects must come
        // back empty, not as a fifty-year delay.
        assertThat(RetryAfter.parse("Friday, 06-Nov-76 08:49:37 GMT", NOW_2026)).isEmpty();
    }

    @Test
    void rfc850TwoDigitYearFiftyOneYearsAheadRollsBackACentury() {
        // Low-end guard: "77" reads as 1977 within [1977, 2076] — already in the past, no
        // century shift involved. 1977-11-06 was a Sunday; ZERO, since the date has passed.
        assertThat(RetryAfter.parse("Sunday, 06-Nov-77 08:49:37 GMT", NOW_2026)).contains(Duration.ZERO);
    }

    @Test
    void rfc850TwoDigitYearNearNowStaysInTheCurrentCentury() {
        // Guards against over-correction: "26" with "now" in 2026 is 2026 itself, still ahead
        // of the pinned now. 2026-11-06 is a Friday.
        assertThat(RetryAfter.parse("Friday, 06-Nov-26 08:49:37 GMT", NOW_2026))
                .contains(Duration.between(NOW_2026, Instant.parse("2026-11-06T08:49:37Z")));
    }

    @Test
    void rfc850TwoDigitYearWindowFollowsNow() {
        // The same bytes resolve differently as "now" moves — this is what pins the window to
        // "now" rather than to any hard-coded base year.
        String header = "Sunday, 06-Nov-94 08:49:37 GMT";
        assertThat(RetryAfter.parse(header, NOW_2026))
                .as("in 2026, 94 is 1994 (a Sunday): parseable, in the past")
                .contains(Duration.ZERO);
        assertThat(RetryAfter.parse(header, Instant.parse("2126-08-01T00:00:00Z")))
                .as("a century later, 94 is 2094 — a Saturday, so the stated Sunday matches only"
                        + " 1994, a reading the rule no longer allows: empty, which also pins that the"
                        + " previous-century fallback stays off while the recent reading is within 50"
                        + " years; a base year frozen at 2026 would still return ZERO")
                .isEmpty();
    }

    @Test
    void rfc850LeapSecondCarryingTheTimestampPastFiftyYearsRollsBackACentury() {
        // The century decision must see the final instant, leap-second increment included.
        // now + 50y = 2076-12-31T23:59:59Z; the :60 normalises to :59 (equal to the horizon)
        // but the +1s carries the final instant to 2077-01-01T00:00:00Z — more than 50 years
        // ahead — so the header means 1976-12-31T23:59:60 (a Friday), i.e. 1977-01-01T00:00:00Z,
        // in the past: ZERO. Deciding the century on the pre-increment instant kept 2076, whose
        // Thursday then failed the weekday cross-check and dropped this correct header.
        Instant nowAtBoundary = Instant.parse("2026-12-31T23:59:59Z");
        assertThat(RetryAfter.parse("Friday, 31-Dec-76 23:59:60 GMT", nowAtBoundary))
                .contains(Duration.ZERO);
    }

    @Test
    void rfc850LeapSecondPastFiftyYearsWithTheRejectedCenturysWeekdayIsEmpty() {
        // Same timestamp, but carrying 2076-12-31's weekday (Thursday): the rule reads the
        // adjusted instant as 1976, a Friday, so a Thursday header is self-consistent only in
        // the century the rule rejects — empty, not a fifty-year delay.
        Instant nowAtBoundary = Instant.parse("2026-12-31T23:59:59Z");
        assertThat(RetryAfter.parse("Thursday, 31-Dec-76 23:59:60 GMT", nowAtBoundary))
                .isEmpty();
    }

    @Test
    void rfc850PlainSecondAtTheFiftyYearHorizonStillStaysInTheRecentCentury() {
        // Non-leap control at the same boundary: :59 with no leap second is exactly now + 50
        // calendar years, and the rule is strict ("MORE than 50 years"), so 2076 (a Thursday)
        // stands. This pins that the fix moved only the leap-second case.
        Instant nowAtBoundary = Instant.parse("2026-12-31T23:59:59Z");
        assertThat(RetryAfter.parse("Thursday, 31-Dec-76 23:59:59 GMT", nowAtBoundary))
                .contains(Duration.between(nowAtBoundary, Instant.parse("2076-12-31T23:59:59Z")));
    }

    @Test
    void parsesAsctimeDateAsUtc() {
        assertThat(RetryAfter.parse("Sun Nov  6 08:49:37 2022", NOW)).contains(Duration.ofSeconds(37));
    }

    @Test
    void leapSecondIsAcceptedInEachHttpDateFormat() {
        // HTTP-date allows a seconds value of 60; NOW is 08:49:00, so :60 (= 08:50:00, one
        // second past the :59 instant) must come out as exactly 60 seconds in every format.
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:60 GMT", NOW))
                .as("IMF-fixdate")
                .contains(Duration.ofSeconds(60));
        assertThat(RetryAfter.parse("Sunday, 06-Nov-22 08:49:60 GMT", NOW))
                .as("RFC 850")
                .contains(Duration.ofSeconds(60));
        assertThat(RetryAfter.parse("Sun Nov  6 08:49:60 2022", NOW))
                .as("asctime")
                .contains(Duration.ofSeconds(60));
    }

    @Test
    void nonLeapSecondsValueParsesUnchanged() {
        // Guard against the leap-second normalisation firing on an ordinary value: :59 is 59
        // seconds after NOW, not 60.
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:59 GMT", NOW)).contains(Duration.ofSeconds(59));
    }

    @Test
    void sixtyOutsideTheSecondsFieldDoesNotTriggerLeapSecondHandling() {
        // A "60" in the year must not be rewritten: the delay to 2060-11-06T08:49:37Z (a
        // Saturday) must be exact, not one second longer.
        assertThat(RetryAfter.parse("Sat, 06 Nov 2060 08:49:37 GMT", NOW))
                .contains(Duration.between(NOW, Instant.parse("2060-11-06T08:49:37Z")));
        // A "60" in the minutes field is plain invalid — not a leap second, never normalised.
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:60:37 GMT", NOW)).isEmpty();
    }

    @Test
    void manyLeapSecondGroupsAreRejectedWithoutRescanningThroughThem() {
        // The header comes from the remote push service, so its size and shape are hostile
        // input. Normalising every HH:MM:60 group in turn would be quadratic and would recurse
        // once per group — tens of kilobytes were enough to exhaust the stack, throwing out of
        // a parser whose contract is to never throw. Only the first group is substituted, and a
        // value with a second time-of-day is malformed anyway, so it must simply come back empty.
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:60 08:49:60 GMT", NOW))
                .as("two time-of-day groups is not a valid HTTP-date")
                .isEmpty();

        String hostile = "Sun, 06 Nov 2022 " + "08:49:60 ".repeat(20_000) + "GMT";
        assertThat(RetryAfter.parse(hostile, NOW))
                .as("a large adversarial value returns empty rather than throwing")
                .isEmpty();
    }

    @Test
    void dateAtOrBeforeNowYieldsZero() {
        assertThat(RetryAfter.parse("Sat, 05 Nov 2022 08:49:00 GMT", NOW))
                .as("date in the past")
                .contains(Duration.ZERO);
        assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:00 GMT", NOW))
                .as("date exactly at now")
                .contains(Duration.ZERO);
    }

    @Test
    void deltaSecondsOverflowingALongIsEmptyNotAnException() {
        assertThat(RetryAfter.parse("99999999999999999999", NOW)).isEmpty();
    }

    @Test
    void aDayOfMonthThatDoesNotExistIsRejectedInEachHttpDateFormat() {
        // 2023 is not a leap year. Each value states the weekday of 28 Feb 2023 (a Tuesday), which
        // is precisely what java.time's default SMART resolver clamps 29 Feb to — so the weekday
        // cross-check passes and SMART returned a delay a day short of the header's own claim. The
        // HTTP-date grammar admits no such date; STRICT resolution rejects all three.
        assertThat(RetryAfter.parse("Tue, 29 Feb 2023 08:49:37 GMT", NOW)).isEmpty();
        assertThat(RetryAfter.parse("Tuesday, 29-Feb-23 08:49:37 GMT", NOW)).isEmpty();
        assertThat(RetryAfter.parse("Tue Feb 29 08:49:37 2023", NOW)).isEmpty();
    }

    @Test
    void aRealLeapDayStillParsesInEachHttpDateFormat() {
        // The counterpart to the check above: 29 Feb 2024 exists (a Thursday) and STRICT resolution
        // must not have made the formatters reject valid dates wholesale.
        Duration untilLeapDay = Duration.between(NOW, Instant.parse("2024-02-29T08:49:37Z"));
        assertThat(RetryAfter.parse("Thu, 29 Feb 2024 08:49:37 GMT", NOW)).contains(untilLeapDay);
        assertThat(RetryAfter.parse("Thursday, 29-Feb-24 08:49:37 GMT", NOW)).contains(untilLeapDay);
        assertThat(RetryAfter.parse("Thu Feb 29 08:49:37 2024", NOW)).contains(untilLeapDay);
    }

    @Test
    void garbageIsEmpty() {
        assertThat(RetryAfter.parse("soon", NOW)).isEmpty();
        assertThat(RetryAfter.parse("", NOW)).isEmpty();
        assertThat(RetryAfter.parse("  ", NOW)).isEmpty();
    }

    @Test
    void nonAsciiDigitsAreOutsideTheDeltaSecondsGrammar() {
        // Arabic-Indic "120": Character.isDigit-based parsing would accept it.
        assertThat(RetryAfter.parse("١٢٠", NOW)).isEmpty();
    }

    @Test
    void parsesUnderANonEnglishDefaultLocale() {
        Locale previous = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("ru-RU"));
        try {
            assertThat(RetryAfter.parse("Sun, 06 Nov 2022 08:49:37 GMT", NOW))
                    .as("IMF-fixdate under ru-RU")
                    .contains(Duration.ofSeconds(37));
            assertThat(RetryAfter.parse("Sunday, 06-Nov-22 08:49:37 GMT", NOW))
                    .as("RFC 850 under ru-RU")
                    .contains(Duration.ofSeconds(37));
            assertThat(RetryAfter.parse("Sun Nov  6 08:49:37 2022", NOW))
                    .as("asctime under ru-RU")
                    .contains(Duration.ofSeconds(37));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void dateFormattersAreBoundToTheRootLocale() {
        // The behavioural test above cannot pin this on its own: the asctime formatter is a
        // static field initialised under the ambient locale before any test changes the
        // default, and the RFC 850 formatters a parse uses are memoised, so whether a parse
        // call builds one — and under which default locale — depends on test order. Asserting
        // the binding directly on a freshly built formatter is what makes swapping Locale.ROOT
        // for Locale.getDefault() fail, order-independently.
        assertThat(RetryAfter.rfc850Date(1877).getLocale()).isEqualTo(Locale.ROOT);
        assertThat(RetryAfter.ASCTIME_DATE.getLocale()).isEqualTo(Locale.ROOT);
    }

    @Test
    void rfc850FormatterPairIsMemoisedPerNowYear() {
        // Both century windows live in one memo entry: repeated lookups for the same "now"
        // year must hand back the same formatter instances, whichever window is asked for —
        // a single-formatter memo keyed on the base year would rebuild on alternate calls.
        // The year is one no parse-path test uses, so the first call builds a fresh entry.
        RetryAfter.Rfc850 first = RetryAfter.rfc850Formatters(2033);
        RetryAfter.Rfc850 second = RetryAfter.rfc850Formatters(2033);
        assertThat(second.recentCentury()).isSameAs(first.recentCentury());
        assertThat(second.previousCentury()).isSameAs(first.previousCentury());
    }
}
