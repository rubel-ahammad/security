package com.ideascale.commons.security.core

interface Resource { val id: ResourceId }
interface Action { val id: ActionId }

data class Principal(
  val memberId: Long,
  val workspaceId: Long,
  val roles: Set<String> = emptySet()
)

data class AccessRequest(
  val principal: Principal?, // null => unauthenticated/anonymous
  val resource: Resource,
  val action: Action,
  val resourceId: Long,
  val environment: Map<String, String> = emptyMap()
)
