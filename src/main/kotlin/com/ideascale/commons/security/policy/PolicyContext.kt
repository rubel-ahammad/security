package com.ideascale.commons.security.policy

import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource

data class PolicyContext(
  val principal: Principal?,
  val resource: Resource,
  val action: Action,
  val resourceId: Long,
  val environment: Map<String, String>
)
