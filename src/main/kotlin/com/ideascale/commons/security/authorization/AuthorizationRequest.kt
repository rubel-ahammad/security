package com.ideascale.commons.security.authorization

import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource

data class AuthorizationRequest(
  val principal: Principal?, // null => unauthenticated/anonymous
  val resource: Resource,
  val action: Action,
  val resourceId: Long,
  val environment: Map<String, String> = emptyMap()
)
