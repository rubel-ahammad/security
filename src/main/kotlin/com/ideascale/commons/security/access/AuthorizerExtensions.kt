package com.ideascale.commons.security.access

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.core.Action
import com.ideascale.commons.security.core.Principal
import com.ideascale.commons.security.core.Resource
import com.ideascale.commons.security.internal.AccessDecisionHandlerProvider
import com.ideascale.commons.security.internal.ThrowOnDenyDecisionHandler

fun Authorizer.isAllowed(request: AccessRequest): Boolean = authorize(request).granted

fun Authorizer.check(request: AccessRequest) {
  val decision = authorize(request)
  val handler = (this as? AccessDecisionHandlerProvider)?.accessDecisionHandler
    ?: ThrowOnDenyDecisionHandler
  handler.handle(decision)
}

fun Authorizer.check(
  principal: Principal?,
  resource: Resource,
  action: Action,
  resourceId: Long,
  environment: Map<String, String> = emptyMap()
) {
  check(
    AccessRequest(
      principal = principal,
      resource = resource,
      action = action,
      resourceId = resourceId,
      environment = environment
    )
  )
}
