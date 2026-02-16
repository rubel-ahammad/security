package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.policy.ActionSelection
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyBinding
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.ResourceSelection
import com.ideascale.commons.security.policy.dsl.ActionDslScope
import com.ideascale.commons.security.policy.dsl.PolicyDslScope
import com.ideascale.commons.security.policy.dsl.ResourceDslScope

/**
 * Internal DSL implementation.
 *
 * Public API is the `policies {}` entrypoint and the DSL scope interfaces in policy/dsl.
 */
internal class PolicyConfigBuilder(
  private val version: String
) : PolicyDslScope {

  private val policiesById = LinkedHashMap<PolicyId, Policy>()
  private val bindings = ArrayList<PolicyBinding>()

  override fun resource(resource: Resource, block: ResourceDslScope.() -> Unit) {
    ResourceScope(this, ResourceSelection.Exact(resource.id)).apply(block)
  }

  override fun anyResource(block: ResourceDslScope.() -> Unit) {
    ResourceScope(this, ResourceSelection.Any).apply(block)
  }

  internal fun build(): PolicyConfig =
    PolicyConfig(
      version = version,
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
  private val resourceSelection: ResourceSelection
) : ResourceDslScope {

  override fun action(action: Action, block: ActionDslScope.() -> Unit) {
    ActionScope(root, resourceSelection, ActionSelection.Exact(action.id)).apply(block).register()
  }

  override fun anyAction(block: ActionDslScope.() -> Unit) {
    ActionScope(root, resourceSelection, ActionSelection.Any).apply(block).register()
  }
}

internal class ActionScope(
  private val root: PolicyConfigBuilder,
  private val resourceSelection: ResourceSelection,
  private val actionSelection: ActionSelection
) : ActionDslScope {

  private val policyIds = ArrayList<PolicyId>(4)

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
