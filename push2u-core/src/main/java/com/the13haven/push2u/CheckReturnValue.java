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
 * Marks a method whose returned value is the whole of its answer, so that discarding it discards the answer. It exists
 * for static analysers rather than for the compiler: several of them — Error Prone's <a
 * href="https://errorprone.info/bugpattern/CheckReturnValue">{@code CheckReturnValue}</a> check among them — match an
 * annotation of this <em>simple name</em> whatever package it comes from, so a consumer already running such an
 * analyser has a bare {@code someObject.assess(uri);} statement reported as an error with nothing to configure and no
 * dependency to add.
 *
 * <p>It is declared here, in this library's own package and not taken from an analyser's artifact, because this module
 * carries no runtime dependency beyond a set of annotations that contain no code, and an annotation whose entire
 * purpose is to be read by name does not need to be the one an analyser ships.
 *
 * <p>Nothing is promised beyond that. {@code javac} says nothing about a discarded return value under any option it
 * has, so a consumer without such an analyser sees no diagnostic and loses nothing — an annotation whose type is not on
 * the classpath is ignored, on the class file and in reflection alike. Nor does the mark travel down an inheritance
 * chain: a call made through an implementation type whose own overriding method is unannotated is outside what any of
 * this catches.
 *
 * <p>Not public, and not part of this library's API: a consumer neither writes it nor reads it, and it is left out of
 * the generated documentation of the methods that carry it. Its being present in the class file is the whole of what
 * makes it work, and it is kept readable at run time so that a test in this library can assert by reflection that a
 * refactoring has not quietly dropped it from a method that needs it.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@interface CheckReturnValue {}
