package com.ideascale.commons.security.policy

import com.ideascale.commons.security.model.ActionId
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.ResourceId

data class PolicyConfig(
  val policiesById: Map<PolicyId, Policy>,
  val bindings: List<PolicyBinding>
)

data class PolicyBinding(
  val resource: Selection<ResourceId>,
  val action: Selection<ActionId>,
  val policyIds: List<PolicyId>
)

sealed interface Selection<out T> {
  data object Any : Selection<Nothing>
  data class Exact<T>(val value: T) : Selection<T>
  data class OneOf<T>(val values: Set<T>) : Selection<T>
}
