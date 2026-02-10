package com.ideascale.commons.security.internal

import com.ideascale.commons.security.api.AccessContext
import com.ideascale.commons.security.api.AccessContextFactory
import com.ideascale.commons.security.api.AccessRequest
import com.ideascale.commons.security.api.BasicAccessContext

internal class DefaultAccessContextFactory : AccessContextFactory {
  override fun create(request: AccessRequest): AccessContext = BasicAccessContext(request)
}
