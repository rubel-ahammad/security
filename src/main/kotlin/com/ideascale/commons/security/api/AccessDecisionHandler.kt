package com.ideascale.commons.security.api

fun interface AccessDecisionHandler {
  fun handle(decision: AccessDecision)
}

object DefaultAccessDecisionHandler : AccessDecisionHandler {
  override fun handle(decision: AccessDecision) {
    if (decision is AccessDecision.Deny) {
      throw AccessDeniedException(decision)
    }
  }
}

interface AccessDecisionHandlerProvider {
  val accessDecisionHandler: AccessDecisionHandler
}

class DecisionHandlingAuthorizer(
  private val delegate: Authorizer,
  override val accessDecisionHandler: AccessDecisionHandler
) : Authorizer, AccessDecisionHandlerProvider {
  override fun authorize(request: AccessRequest): AccessDecision =
    delegate.authorize(request)
}
