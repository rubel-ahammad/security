package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.internal.DefaultAuthorizer
import com.ideascale.commons.security.internal.DefaultPolicyResolver
import com.ideascale.commons.security.internal.DecisionHandlingAuthorizer
import com.ideascale.commons.security.internal.PolicyEngine
import com.ideascale.commons.security.internal.DefaultDenyExceptionFactory
import com.ideascale.commons.security.policy.PolicyConfig

class AuthorizerBuilder(
  private val config: PolicyConfig
) {
  private var denyExceptionFactory: DenyExceptionFactory = DefaultDenyExceptionFactory

  fun denyExceptionFactory(factory: DenyExceptionFactory): AuthorizerBuilder = apply {
    this.denyExceptionFactory = factory
  }

  fun build(): Authorizer {
    val delegate = DefaultAuthorizer(
      config = config,
      policyResolver = DefaultPolicyResolver(config),
      engine = PolicyEngine()
    )
    return DecisionHandlingAuthorizer(delegate, denyExceptionFactory)
  }
}
