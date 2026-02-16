package com.ideascale.commons.security.policy

import com.ideascale.commons.security.model.DenyReason
import com.ideascale.commons.security.model.PolicyId

interface Policy {
  val id: PolicyId
  fun evaluate(ctx: PolicyContext): PolicyEffect
}

/**
 * The effect of an individual policy evaluation.
 */
sealed interface PolicyEffect {
  data object Allow : PolicyEffect
  data object NotApplicable : PolicyEffect
  data class Deny(val reason: DenyReason? = null) : PolicyEffect
}
