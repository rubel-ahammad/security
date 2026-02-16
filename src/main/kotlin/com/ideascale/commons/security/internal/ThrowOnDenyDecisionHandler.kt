package com.ideascale.commons.security.internal

import com.ideascale.commons.security.authorization.AuthorizationDecision
import com.ideascale.commons.security.authorization.AuthorizationDecisionHandler
import com.ideascale.commons.security.authorization.AccessDeniedException

internal object ThrowOnDenyDecisionHandler : AuthorizationDecisionHandler {
  override fun handle(decision: AuthorizationDecision) {
    if (decision is AuthorizationDecision.Deny) {
      throw AccessDeniedException(decision)
    }
  }
}
