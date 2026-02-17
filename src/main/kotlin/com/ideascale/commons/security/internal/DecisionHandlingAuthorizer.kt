package com.ideascale.commons.security.internal

import com.ideascale.commons.security.authorization.AuthorizationRequest
import com.ideascale.commons.security.authorization.AuthorizationDecision
import com.ideascale.commons.security.authorization.DenyExceptionFactory
import com.ideascale.commons.security.authorization.Authorizer

internal class DecisionHandlingAuthorizer(
  private val delegate: Authorizer,
  private val denyExceptionFactory: DenyExceptionFactory
) : Authorizer {
  override fun authorize(request: AuthorizationRequest): AuthorizationDecision =
    delegate.authorize(request)

  override fun check(request: AuthorizationRequest) {
    val decision = delegate.authorize(request)
    if (decision is AuthorizationDecision.Deny) {
      throw denyExceptionFactory.create(decision)
    }
  }
}
