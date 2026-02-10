package com.ideascale.commons.security.api

import com.ideascale.commons.security.internal.DefaultAccessContextFactory
import com.ideascale.commons.security.internal.DefaultAuthorizer
import com.ideascale.commons.security.internal.DefaultPolicyResolver
import com.ideascale.commons.security.internal.PolicyEngine

class AuthorizerBuilder(
  private val config: PolicyConfig
) {
  private var contextFactory: AccessContextFactory = DefaultAccessContextFactory()

  fun contextFactory(factory: AccessContextFactory): AuthorizerBuilder = apply {
    this.contextFactory = factory
  }

  fun build(): Authorizer =
    DefaultAuthorizer(
      config = config,
      contextFactory = contextFactory,
      policyResolver = DefaultPolicyResolver(config),
      engine = PolicyEngine()
    )
}
