package com.ideascale.commons.security.api

interface AccessContext {
  val request: AccessRequest
}

fun interface AccessContextFactory {
  fun create(request: AccessRequest): AccessContext
}

data class BasicAccessContext(
  override val request: AccessRequest
) : AccessContext
