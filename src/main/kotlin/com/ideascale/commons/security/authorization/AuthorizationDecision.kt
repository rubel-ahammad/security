package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.model.DenyReason
import com.ideascale.commons.security.model.PolicyId

sealed interface AuthorizationDecision {
  val decidedByPolicyId: PolicyId?
  val granted: Boolean

  data object Allow : AuthorizationDecision {
    override val decidedByPolicyId: PolicyId? = null
    override val granted: Boolean = true
  }

  data class Deny(
    val reason: DenyReason,
    override val decidedByPolicyId: PolicyId? = null
  ) : AuthorizationDecision {
    override val granted: Boolean = false
  }
}
