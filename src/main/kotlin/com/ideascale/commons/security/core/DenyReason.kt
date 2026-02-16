package com.ideascale.commons.security.core

data class DenyReason(
  val code: String,
  val details: Map<String, String> = emptyMap()
)
