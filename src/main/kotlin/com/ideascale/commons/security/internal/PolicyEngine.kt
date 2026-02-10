package com.ideascale.commons.security.internal

import com.ideascale.commons.security.api.AccessContext
import com.ideascale.commons.security.api.AccessDecision
import com.ideascale.commons.security.api.DenyReason
import com.ideascale.commons.security.api.Policy
import com.ideascale.commons.security.api.PolicyEffect

/**
 * Hard-coded v1 semantics:
 * - Deny overrides (first deny wins)
 * - Any allow (and no denies) => allow
 * - Otherwise => default deny
 *
 * Also:
 * - Policies are evaluated lazily in a loop
 * - Exceptions in policy evaluation fail closed (deny)
 */
internal class PolicyEngine {
  private val DEFAULT_DENY = DenyReason(code = "default-deny")

  fun evaluate(policies: List<Policy>, ctx: AccessContext): AccessDecision {
    var sawAllow = false

    for (p in policies) {
      val effect: PolicyEffect = try {
        p.evaluate(ctx)
      } catch (e: Exception) {
        // Fail closed: exception becomes Deny and short-circuits immediately
        PolicyEffect.Deny(
          DenyReason(
            code = "exception",
            details = mapOf(
              "phase" to "policy-evaluate",
              "policyId" to p.id.value,
              "exceptionType" to (e::class.simpleName ?: "Exception")
            )
          )
        )
      }

      when (effect) {
        is PolicyEffect.Deny -> {
          val reason = effect.reason ?: DenyReason(code = p.id.value)
          return AccessDecision.Deny(reason, decidedByPolicyId = p.id)
        }
        PolicyEffect.Allow -> sawAllow = true
        PolicyEffect.NotApplicable -> Unit
      }
    }

    return if (sawAllow) AccessDecision.Allow
    else AccessDecision.Deny(DEFAULT_DENY)
  }
}
