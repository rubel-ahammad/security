package com.ideascale.commons.security.internal

import com.ideascale.commons.security.authorization.AuthorizationDecisionHandler

internal interface AuthorizationDecisionHandlerProvider {
  val authorizationDecisionHandler: AuthorizationDecisionHandler
}
