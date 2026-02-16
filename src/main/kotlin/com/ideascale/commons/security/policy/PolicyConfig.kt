package com.ideascale.commons.security.policy

import com.ideascale.commons.security.core.ActionId
import com.ideascale.commons.security.core.PolicyId
import com.ideascale.commons.security.core.ResourceId

data class PolicyConfig(
  val version: String,
  val policiesById: Map<PolicyId, Policy>,
  val bindings: List<PolicyBinding>
)

data class PolicyBinding(
  val resource: ResourceSelection,
  val action: ActionSelection,
  val policyIds: List<PolicyId>
)

/**
 * Resource selection applies to AccessRequest.resource.id (resource "type").
 */
sealed interface ResourceSelection {
  data object Any : ResourceSelection
  data class Exact(val id: ResourceId) : ResourceSelection
  data class OneOf(val ids: Set<ResourceId>) : ResourceSelection
}

/**
 * Action selection applies to AccessRequest.action.id.
 */
sealed interface ActionSelection {
  data object Any : ActionSelection
  data class Exact(val id: ActionId) : ActionSelection
  data class OneOf(val ids: Set<ActionId>) : ActionSelection
}
