package com.ideascale.commons.security.api

fun interface Authorizer {
  fun authorize(request: AccessRequest): AccessDecision

  /**
   * Convenience overload (still uses Resource/Action).
   */
  fun authorize(
    principal: Principal?,
    resource: Resource,
    action: Action,
    resourceId: Long,
    environment: Map<String, String> = emptyMap()
  ): AccessDecision = authorize(
    AccessRequest(
      principal = principal,
      resource = resource,
      action = action,
      resourceId = resourceId,
      environment = environment
    )
  )
}

fun Authorizer.isAllowed(request: AccessRequest): Boolean = authorize(request).granted

class AccessDeniedException(val decision: AccessDecision.Deny) :
  RuntimeException("Access denied: ${decision.reason.code}")

fun Authorizer.check(request: AccessRequest) {
  when (val d = authorize(request)) {
    AccessDecision.Allow -> Unit
    is AccessDecision.Deny -> throw AccessDeniedException(d)
  }
}
