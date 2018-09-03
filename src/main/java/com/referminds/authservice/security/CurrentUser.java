package com.referminds.authservice.security;


import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.core.annotation.AuthenticationPrincipal;



/**
 * 
 * Spring security provides an annotation called @{@link AuthenticationPrincipal} to access the currently authenticated user in the controllers.
 * The following CurrentUser annotation is a wrapper around @{@link AuthenticationPrincipal} annotation.
 * We’ve created a meta-annotation so that we don’t get too much tied up of with Spring Security related annotations everywhere in our project. 
 * This reduces the dependency on Spring Security. So if we decide to remove Spring Security from our project, 
 * we can easily do it by simply changing the {@link CurrentUser} annotation-
 * 
 * @author rahul.sharma3
 *
 */
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {

}