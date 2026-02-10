package com.ideascale.commons.security.api

import com.ideascale.commons.security.internal.DefaultAccessContextFactory
import com.ideascale.commons.security.internal.DefaultAuthorizer
import com.ideascale.commons.security.internal.DefaultPolicyResolver
import com.ideascale.commons.security.internal.PolicyEngine

object Authorizers {
  fun from(config: PolicyConfig): Authorizer =
    DefaultAuthorizer(
      config = config,
      contextFactory = DefaultAccessContextFactory(),
      policyResolver = DefaultPolicyResolver(config),
      engine = PolicyEngine()
    )
}
