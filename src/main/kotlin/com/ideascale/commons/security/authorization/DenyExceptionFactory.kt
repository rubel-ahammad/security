package com.ideascale.commons.security.authorization

fun interface DenyExceptionFactory {
  fun create(deny: AuthorizationDecision.Deny): RuntimeException
}
