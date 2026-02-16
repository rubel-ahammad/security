package com.ideascale.commons.security.policy

import com.ideascale.commons.security.model.AuthorizationRequest

data class PolicyContext(
  val request: AuthorizationRequest
)

fun interface PolicyContextFactory {
  fun create(request: AuthorizationRequest): PolicyContext
}
