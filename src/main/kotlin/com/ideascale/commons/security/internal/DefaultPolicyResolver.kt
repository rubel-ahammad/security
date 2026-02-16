package com.ideascale.commons.security.internal

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.core.ActionId
import com.ideascale.commons.security.core.PolicyId
import com.ideascale.commons.security.core.ResourceId
import com.ideascale.commons.security.policy.ActionSelection
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.ResourceSelection

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

  override fun resolve(request: AccessRequest): List<Policy> {
    val resourceType: ResourceId = request.resource.id
    val actionId: ActionId = request.action.id

    val out = ArrayList<Policy>(8)
    val seen = LinkedHashSet<PolicyId>()

    for (b in config.bindings) {
      if (b.resource.matches(resourceType) && b.action.matches(actionId)) {
        for (pid in b.policyIds) {
          if (seen.add(pid)) {
            out += checkNotNull(config.policiesById[pid]) { "Unknown policy id '$pid' at runtime" }
          }
        }
      }
    }
    return out
  }

  private fun ResourceSelection.matches(resourceType: ResourceId): Boolean =
    when (this) {
      ResourceSelection.Any -> true
      is ResourceSelection.Exact -> this.id == resourceType
      is ResourceSelection.OneOf -> resourceType in this.ids
    }

  private fun ActionSelection.matches(actionId: ActionId): Boolean =
    when (this) {
      ActionSelection.Any -> true
      is ActionSelection.Exact -> this.id == actionId
      is ActionSelection.OneOf -> actionId in this.ids
    }
}
