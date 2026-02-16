package com.ideascale.commons.security.internal

import com.ideascale.commons.security.model.DenyReason

internal object DenyReasons {
  val defaultDeny: DenyReason = DenyReason(code = "default-deny")

  fun exception(
    phase: String,
    exception: Exception,
    details: Map<String, String> = emptyMap()
  ): DenyReason = DenyReason(
    code = "exception",
    details = mapOf(
      "phase" to phase,
      "exceptionType" to exception.javaClass.name
    ) + details
  )
}
