package com.ideascale.commons.security.api

import com.ideascale.commons.security.internal.DefaultAccessContextFactory
import com.ideascale.commons.security.internal.DefaultAuthorizer
import com.ideascale.commons.security.internal.DefaultPolicyResolver
import com.ideascale.commons.security.internal.PolicyEngine

class AuthorizerBuilder(
  private val config: PolicyConfig
) {
  private var contextFactory: AccessContextFactory = DefaultAccessContextFactory()
  private var decisionHandler: AccessDecisionHandler = DefaultAccessDecisionHandler

  fun contextFactory(factory: AccessContextFactory): AuthorizerBuilder = apply {
    this.contextFactory = factory
  }

  fun decisionHandler(handler: AccessDecisionHandler): AuthorizerBuilder = apply {
    this.decisionHandler = handler
  }

  fun build(): Authorizer {
    val delegate = DefaultAuthorizer(
      config = config,
      contextFactory = contextFactory,
      policyResolver = DefaultPolicyResolver(config),
      engine = PolicyEngine()
    )
    return DecisionHandlingAuthorizer(delegate, decisionHandler)
  }
}
