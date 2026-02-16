package com.ideascale.commons.security.internal

import com.ideascale.commons.security.access.AccessDecisionHandler

internal interface AccessDecisionHandlerProvider {
  val accessDecisionHandler: AccessDecisionHandler
}
