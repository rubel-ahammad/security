package com.ideascale.commons.security.api

data class DenyReason(
  val code: String,
  val details: Map<String, String> = emptyMap()
)
