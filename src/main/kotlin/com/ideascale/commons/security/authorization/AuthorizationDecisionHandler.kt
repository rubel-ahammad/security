package com.ideascale.commons.security.authorization

fun interface AuthorizationDecisionHandler {
  fun handle(decision: AuthorizationDecision)
}
