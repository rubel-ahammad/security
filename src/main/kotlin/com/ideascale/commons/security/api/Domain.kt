package com.ideascale.commons.security.api

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
  /**
   * Resource instance id (e.g., ideaId). The framework routes by Resource.id/Action.id;
   * policies use resourceId to load/verify specific instances.
   */
  val resourceId: Long,
  val environment: Map<String, String> = emptyMap()
)
