package com.ideascale.commons.security.policy.dsl

import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.internal.PolicyConfigBuilder
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyConfig

@DslMarker
annotation class PolicyDslMarker

/**
 * Root scope is intentionally minimal: you can only describe bindings.
 * No top-level `+Policy` registration here.
 */
@PolicyDslMarker
interface PolicyDslScope {
  fun resource(resource: Resource, block: ResourceDslScope.() -> Unit)
  fun anyResource(block: ResourceDslScope.() -> Unit)
}

@PolicyDslMarker
interface ResourceDslScope {
  fun action(action: Action, block: ActionDslScope.() -> Unit)
  fun anyAction(block: ActionDslScope.() -> Unit)
}

@PolicyDslMarker
interface ActionDslScope {
  operator fun Policy.unaryPlus()
}

/**
 * Public entrypoint for building a PolicyConfig.
 *
 * Implementation details live in internal builder classes.
 */
fun policies(block: PolicyDslScope.() -> Unit): PolicyConfig = PolicyConfigBuilder()
  .apply(block)
  .build()
