package com.ideascale.commons.security.internal

import com.ideascale.commons.security.authorization.AuthorizationDecision
import com.ideascale.commons.security.authorization.AuthorizationDecisionHandler
import com.ideascale.commons.security.authorization.Authorizer
import com.ideascale.commons.security.model.AuthorizationRequest

internal class DecisionHandlingAuthorizer(
  private val delegate: Authorizer,
  override val authorizationDecisionHandler: AuthorizationDecisionHandler
) : Authorizer, AuthorizationDecisionHandlerProvider {
  override fun authorize(request: AuthorizationRequest): AuthorizationDecision =
    delegate.authorize(request)

  override fun check(request: AuthorizationRequest) {
    val decision = delegate.authorize(request)
    authorizationDecisionHandler.handle(decision)
  }
}
