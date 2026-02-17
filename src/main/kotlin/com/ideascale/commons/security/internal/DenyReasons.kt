package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.Reason

internal object DenyReasons {
  private const val EXCEPTION_CODE = "exception"
  private const val PHASE_KEY = "phase"
  private const val EXCEPTION_TYPE_KEY = "exceptionType"

  val defaultDeny: Reason = Reason(code = "default-deny")

  fun exception(
    phase: String,
    exception: Exception,
    details: Map<String, String> = emptyMap()
  ): Reason = Reason(
    code = EXCEPTION_CODE,
    details = mapOf(
      PHASE_KEY to phase,
      EXCEPTION_TYPE_KEY to exception.javaClass.name
    ) + details
  )
}
