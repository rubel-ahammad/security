package com.ideascale.commons.security.model

interface Resource { val id: ResourceId }
interface Action { val id: ActionId }

data class Principal(
  val memberId: Long,
  val workspaceId: Long,
  val roles: Set<String> = emptySet()
)

data class Reason(
  val code: String,
  val details: Map<String, String> = emptyMap()
)
