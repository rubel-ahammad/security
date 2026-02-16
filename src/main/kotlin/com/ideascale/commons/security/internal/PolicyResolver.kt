package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.policy.Policy

internal fun interface PolicyResolver {
  fun resolve(request: AuthorizationRequest): List<Policy>
}
