package com.osatum.wbn.application.journal.authorization;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Stosuje wspólną regułę dostępu do katalogu, ankiet i eksportów, żeby pobranie pliku nie omijało ograniczeń katalogu.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@journalAuthorization.canJournalView()")
public @interface CanJournalView {
}
