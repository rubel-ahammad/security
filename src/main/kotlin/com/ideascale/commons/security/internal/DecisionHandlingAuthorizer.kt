package com.ideascale.commons.security.internal

import com.ideascale.commons.security.access.AccessDecision
import com.ideascale.commons.security.access.AccessDecisionHandler
import com.ideascale.commons.security.access.Authorizer
import com.ideascale.commons.security.core.AccessRequest

internal class DecisionHandlingAuthorizer(
  private val delegate: Authorizer,
  override val accessDecisionHandler: AccessDecisionHandler
) : Authorizer, AccessDecisionHandlerProvider {
  override fun authorize(request: AccessRequest): AccessDecision =
    delegate.authorize(request)
}
