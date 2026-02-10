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
  val decision = authorize(request)
  val handler = (this as? AccessDecisionHandlerProvider)?.accessDecisionHandler
    ?: DefaultAccessDecisionHandler
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
