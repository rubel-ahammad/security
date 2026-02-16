package com.ideascale.commons.security.policy

import com.ideascale.commons.security.core.AccessRequest

data class PolicyContext(
  val request: AccessRequest
)

fun interface PolicyContextFactory {
  fun create(request: AccessRequest): PolicyContext
}
