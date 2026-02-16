package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.policy.PolicyContext
import com.ideascale.commons.security.policy.PolicyContextFactory

internal class DefaultPolicyContextFactory : PolicyContextFactory {
  override fun create(request: AuthorizationRequest): PolicyContext = PolicyContext(request)
}
