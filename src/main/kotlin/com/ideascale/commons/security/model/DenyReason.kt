package com.ideascale.commons.security.model

data class DenyReason(
  val code: String,
  val details: Map<String, String> = emptyMap()
)
