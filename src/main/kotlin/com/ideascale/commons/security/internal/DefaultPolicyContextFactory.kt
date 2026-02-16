package com.ideascale.commons.security.internal

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.policy.PolicyContext
import com.ideascale.commons.security.policy.PolicyContextFactory

internal class DefaultPolicyContextFactory : PolicyContextFactory {
  override fun create(request: AccessRequest): PolicyContext = PolicyContext(request)
}
