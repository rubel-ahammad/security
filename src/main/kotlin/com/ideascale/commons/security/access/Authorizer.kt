package com.ideascale.commons.security.access

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.core.Action
import com.ideascale.commons.security.core.Principal
import com.ideascale.commons.security.core.Resource

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
