package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource

fun interface Authorizer {
  fun authorize(request: AuthorizationRequest): AuthorizationDecision

  /**
   * Authorizes and throws when denied.
   *
   * Default behavior is throw-on-deny. Builder-produced authorizers may override this behavior
   * via a configured [AuthorizationDecisionHandler].
   */
  fun check(request: AuthorizationRequest) {
    val decision = authorize(request)
    if (decision is AuthorizationDecision.Deny) {
      throw AccessDeniedException(decision)
    }
  }

  /**
   * Convenience overload (still uses Resource/Action).
   */
  fun authorize(
    principal: Principal?,
    resource: Resource,
    action: Action,
    resourceId: Long,
    environment: Map<String, String> = emptyMap()
  ): AuthorizationDecision = authorize(
    AuthorizationRequest(
      principal = principal,
      resource = resource,
      action = action,
      resourceId = resourceId,
      environment = environment
    )
  )

  fun check(
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
}
