package com.ideascale.commons.security.internal

import com.ideascale.commons.security.api.AccessRequest
import com.ideascale.commons.security.api.Policy

internal fun interface PolicyResolver {
  fun resolve(request: AccessRequest): List<Policy>
}
