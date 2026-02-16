package com.ideascale.commons.security.internal

import com.ideascale.commons.security.access.AccessDecision
import com.ideascale.commons.security.access.AccessDecisionHandler
import com.ideascale.commons.security.access.AccessDeniedException

internal object ThrowOnDenyDecisionHandler : AccessDecisionHandler {
  override fun handle(decision: AccessDecision) {
    if (decision is AccessDecision.Deny) {
      throw AccessDeniedException(decision)
    }
  }
}
