package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.internal.AuthorizationDecisionHandlerProvider
import com.ideascale.commons.security.internal.ThrowOnDenyDecisionHandler

fun Authorizer.isAllowed(request: AuthorizationRequest): Boolean = authorize(request).granted

fun Authorizer.check(request: AuthorizationRequest) {
  val decision = authorize(request)
  val handler = (this as? AuthorizationDecisionHandlerProvider)?.authorizationDecisionHandler
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
    AuthorizationRequest(
      principal = principal,
      resource = resource,
      action = action,
      resourceId = resourceId,
      environment = environment
    )
  )
}
