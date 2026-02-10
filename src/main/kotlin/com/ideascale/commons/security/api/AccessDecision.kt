package com.ideascale.commons.security.api

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
