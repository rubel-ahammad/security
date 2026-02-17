package com.ideascale.commons.security.authorization

class AccessDeniedException(val decision: AuthorizationDecision.Deny) :
  RuntimeException("Access denied: ${decision.reason.code}")
