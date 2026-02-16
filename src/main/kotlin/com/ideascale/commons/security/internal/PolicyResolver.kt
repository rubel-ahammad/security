package com.ideascale.commons.security.internal

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.policy.Policy

internal fun interface PolicyResolver {
  fun resolve(request: AccessRequest): List<Policy>
}
