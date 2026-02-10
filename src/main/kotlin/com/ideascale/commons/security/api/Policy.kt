package com.ideascale.commons.security.api

interface Policy {
  val id: PolicyId
  fun evaluate(ctx: AccessContext): PolicyEffect
}

/**
 * The effect of an individual policy evaluation.
 */
sealed interface PolicyEffect {
  data object Allow : PolicyEffect
  data object NotApplicable : PolicyEffect
  data class Deny(val reason: DenyReason? = null) : PolicyEffect
}

data class PolicyEvaluation(
  val policyId: PolicyId,
  val effect: PolicyEffect
)
