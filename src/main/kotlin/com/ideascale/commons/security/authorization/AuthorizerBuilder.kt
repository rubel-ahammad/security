package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.internal.DefaultAuthorizer
import com.ideascale.commons.security.internal.DefaultPolicyContextFactory
import com.ideascale.commons.security.internal.DefaultPolicyResolver
import com.ideascale.commons.security.internal.DecisionHandlingAuthorizer
import com.ideascale.commons.security.internal.PolicyEngine
import com.ideascale.commons.security.internal.DefaultDenyExceptionFactory
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.PolicyContextFactory

class AuthorizerBuilder(
  private val config: PolicyConfig
) {
  private var contextFactory: PolicyContextFactory = DefaultPolicyContextFactory()
  private var denyExceptionFactory: DenyExceptionFactory = DefaultDenyExceptionFactory

  fun contextFactory(factory: PolicyContextFactory): AuthorizerBuilder = apply {
    this.contextFactory = factory
  }

  fun denyExceptionFactory(factory: DenyExceptionFactory): AuthorizerBuilder = apply {
    this.denyExceptionFactory = factory
  }

  fun build(): Authorizer {
    val delegate = DefaultAuthorizer(
      config = config,
      contextFactory = contextFactory,
      policyResolver = DefaultPolicyResolver(config),
      engine = PolicyEngine()
    )
    return DecisionHandlingAuthorizer(delegate, denyExceptionFactory)
  }
}
