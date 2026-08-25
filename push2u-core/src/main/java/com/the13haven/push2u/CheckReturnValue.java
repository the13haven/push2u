/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method whose returned value is the whole of its answer: the call reports nothing, changes nothing and refuses
 * nothing on its own, so discarding the value is indistinguishable from never having asked and leaves the caller
 * believing a check was made. That last clause is what separates such a method from an ordinary accessor, whose
 * discarded value leaves nobody believing anything, and from a capability question whose discard hides nothing because
 * the operation behind it refuses loudly.
 *
 * <p>It exists for static analysers rather than for the compiler: an analyser that matches a mark of this <em>simple
 * name</em>, whatever package it comes from, reports a call that throws the answer away — a bare
 * {@code someObject.assess(uri);} statement, and a method reference such as {@code list.forEach(someObject::assess)}
 * alike. Error Prone's <a href="https://errorprone.info/bugpattern/CheckReturnValue">{@code CheckReturnValue}</a> check
 * is the one this was measured against: it matches by simple name, is on by default at {@code ERROR} severity, and so
 * costs a consumer already running it no configuration and no dependency. What any other analyser or IDE does with this
 * mark is not claimed here, because it was not measured.
 *
 * <p>It is declared here, in this library's own package and not taken from an analyser's artifact, because this module
 * carries no runtime dependency beyond a set of annotations that contain no code, and an annotation whose entire
 * purpose is to be read by name does not need to be the one an analyser ships.
 *
 * <p>Nothing is promised beyond that. {@code javac} has no diagnostic for a discarded return value under any option it
 * offers, and no opinion at all about an annotation that no tool in the build acts on — so a consumer compiling without
 * such an analyser sees nothing change. Nor does the mark travel down an inheritance chain: a call made through an
 * implementation type whose own overriding method is unannotated is outside what any of this catches.
 *
 * <p>Not public, so nothing outside this package can name it, and no part of this library's API: a consumer neither
 * writes it nor reads it, and it is left out of the generated documentation of the methods that carry it. Its being
 * present in the class file is the whole of what makes it work, and it is kept readable at run time so that a test in
 * this library can assert by reflection that a refactoring has not quietly dropped it from a method that needs it.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface CheckReturnValue {}
