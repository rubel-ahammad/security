package com.ideascale.commons.security.internal

import com.ideascale.commons.security.authorization.AuthorizationDecision
import com.ideascale.commons.security.authorization.AccessDeniedException
import com.ideascale.commons.security.authorization.DenyExceptionFactory

internal object DefaultDenyExceptionFactory : DenyExceptionFactory {
  override fun create(deny: AuthorizationDecision.Deny): RuntimeException =
    AccessDeniedException(deny)
}
