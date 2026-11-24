package com.osatum.wbn.application.system.authorization;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Wymaga roli administratora w bieżącym kontekście operatora systemowego.
 * Na poziomie klasy obejmuje wszystkie operacje kontrolera.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@systemAuthorization.canSystemManage()")
public @interface CanSystemManage {
}
