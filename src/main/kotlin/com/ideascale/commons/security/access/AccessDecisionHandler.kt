package com.ideascale.commons.security.access

fun interface AccessDecisionHandler {
  fun handle(decision: AccessDecision)
}
