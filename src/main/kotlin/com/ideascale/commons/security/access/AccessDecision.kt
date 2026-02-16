package com.ideascale.commons.security.access

import com.ideascale.commons.security.core.DenyReason
import com.ideascale.commons.security.core.PolicyId

sealed interface AccessDecision {
  val decidedByPolicyId: PolicyId?
  val granted: Boolean

  data object Allow : AccessDecision {
    override val decidedByPolicyId: PolicyId? = null
    override val granted: Boolean = true
  }

  data class Deny(
    val reason: DenyReason,
    override val decidedByPolicyId: PolicyId? = null
  ) : AccessDecision {
    override val granted: Boolean = false
  }
}
