package com.ideascale.commons.security.internal

import com.ideascale.commons.security.core.AccessRequest
import com.ideascale.commons.security.core.DenyReason
import com.ideascale.commons.security.access.AccessDecision
import com.ideascale.commons.security.access.Authorizer
import com.ideascale.commons.security.policy.PolicyConfig
import com.ideascale.commons.security.policy.PolicyContext
import com.ideascale.commons.security.policy.PolicyContextFactory

/**
 * Facade over the authorization pipeline:
 * - create context
 * - resolve Policy instances
 * - evaluate with hard-coded semantics
 *
 * Any exception fails closed (deny) with phase info.
 */
internal class DefaultAuthorizer(
  private val config: PolicyConfig,
  private val contextFactory: PolicyContextFactory,
  private val policyResolver: PolicyResolver,
  private val engine: PolicyEngine
) : Authorizer {

  init {
    // Fail fast at startup: all referenced policy IDs must exist.
    val known = config.policiesById.keys
    val referenced = config.bindings.asSequence().flatMap { it.policyIds.asSequence() }.toSet()
    val missing = referenced - known
    require(missing.isEmpty()) { "Unknown policy ids in bindings: $missing" }
  }

  override fun authorize(request: AccessRequest): AccessDecision {
    val ctx: PolicyContext = try {
      contextFactory.create(request)
    } catch (e: Exception) {
      return denyException("context-create", e)
    }

    val policies = try {
      policyResolver.resolve(request)
    } catch (e: Exception) {
      return denyException("policy-resolve", e)
    }

    return try {
      engine.evaluate(policies, ctx)
    } catch (e: Exception) {
      denyException("engine-evaluate", e)
    }
  }

  private fun denyException(phase: String, e: Exception): AccessDecision.Deny =
    AccessDecision.Deny(
      DenyReason(
        code = "exception",
        details = mapOf(
          "phase" to phase,
          "exceptionType" to (e::class.simpleName ?: "Exception")
        )
      )
    )
}
