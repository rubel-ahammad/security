package com.ideascale.commons.security.dsl

import com.ideascale.commons.security.api.Action
import com.ideascale.commons.security.api.Policy
import com.ideascale.commons.security.api.PolicyConfig
import com.ideascale.commons.security.api.Resource
import com.ideascale.commons.security.internal.PolicyConfigBuilder

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
fun policies(
  version: String = "1",
  block: PolicyDslScope.() -> Unit
): PolicyConfig = PolicyConfigBuilder(version)
  .apply(block)
  .build()
