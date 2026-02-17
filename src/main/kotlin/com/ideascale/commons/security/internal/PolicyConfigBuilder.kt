package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.ActionId
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.model.ResourceId
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyBinding
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.Selection
import com.ideascale.commons.security.policy.dsl.ActionDslScope
import com.ideascale.commons.security.policy.dsl.PolicyDslScope
import com.ideascale.commons.security.policy.dsl.ResourceDslScope

/**
 * Internal DSL implementation.
 *
 * Public API is the `policies {}` entrypoint and the DSL scope interfaces in policy/dsl.
 */
internal class PolicyConfigBuilder : PolicyDslScope {

  private val policiesById = linkedMapOf<PolicyId, Policy>()
  private val bindings = mutableListOf<PolicyBinding>()

  override fun resource(resource: Resource, block: ResourceDslScope.() -> Unit) {
    ResourceScope(this, Selection.Exact(resource.id)).apply(block)
  }

  override fun anyResource(block: ResourceDslScope.() -> Unit) {
    ResourceScope(this, Selection.Any).apply(block)
  }

  internal fun build(): PolicyConfig =
    PolicyConfig(
      policiesById = policiesById.toMap(),
      bindings = bindings.toList()
    )

  internal fun registerPolicy(policy: Policy) {
    val existing = policiesById.putIfAbsent(policy.id, policy)
    require(existing == null || existing === policy) {
      "Duplicate policy id '${policy.id}' registered with a different instance"
    }
  }

  internal fun addBinding(binding: PolicyBinding) {
    bindings += binding
  }
}

internal class ResourceScope(
  private val root: PolicyConfigBuilder,
  private val resourceSelection: Selection<ResourceId>
) : ResourceDslScope {

  override fun action(action: Action, block: ActionDslScope.() -> Unit) {
    ActionScope(root, resourceSelection, Selection.Exact(action.id)).apply(block).register()
  }

  override fun anyAction(block: ActionDslScope.() -> Unit) {
    ActionScope(root, resourceSelection, Selection.Any).apply(block).register()
  }
}

internal class ActionScope(
  private val root: PolicyConfigBuilder,
  private val resourceSelection: Selection<ResourceId>,
  private val actionSelection: Selection<ActionId>
) : ActionDslScope {

  private val policyIds = mutableListOf<PolicyId>()

  override operator fun Policy.unaryPlus() {
    root.registerPolicy(this)
    policyIds += this.id
  }

  fun register() {
    require(policyIds.isNotEmpty()) {
      "No policies registered for (resource=$resourceSelection, action=$actionSelection). Did you forget '+Policy'?"
    }
    root.addBinding(
      PolicyBinding(
        resource = resourceSelection,
        action = actionSelection,
        policyIds = policyIds.toList()
      )
    )
  }
}
