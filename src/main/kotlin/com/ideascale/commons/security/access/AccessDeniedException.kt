package com.ideascale.commons.security.access

class AccessDeniedException(val decision: AccessDecision.Deny) :
  RuntimeException("Access denied: ${decision.reason.code}")
