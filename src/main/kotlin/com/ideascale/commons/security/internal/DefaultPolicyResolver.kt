package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.model.ActionId
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.ResourceId
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.Selection

/**
 * Resolves policies by:
 * - scanning bindings
 * - collecting PolicyIds in execution order (deduped)
 * - mapping ids -> Policy instances via policiesById
 *
 * Config remains serialization-friendly (bindings store ids),
 * while resolver returns Policy instances (no raw ids leaking).
 */
internal class DefaultPolicyResolver(
  private val config: PolicyConfig
) : PolicyResolver {

  override fun resolve(request: AuthorizationRequest): List<Policy> {
    val resourceType: ResourceId = request.resource.id
    val actionId: ActionId = request.action.id

    val resolvedPolicies = mutableListOf<Policy>()
    val seenPolicyIds = linkedSetOf<PolicyId>()

    for (binding in config.bindings) {
      if (binding.resource.matches(resourceType) && binding.action.matches(actionId)) {
        for (policyId in binding.policyIds) {
          if (seenPolicyIds.add(policyId)) {
            resolvedPolicies += checkNotNull(config.policiesById[policyId]) {
              "Unknown policy id '$policyId' at runtime"
            }
          }
        }
      }
    }
    return resolvedPolicies
  }

  private fun <T> Selection<T>.matches(value: T): Boolean =
    when (this) {
      Selection.Any -> true
      is Selection.Exact -> this.value == value
      is Selection.OneOf -> value in this.values
    }
}
