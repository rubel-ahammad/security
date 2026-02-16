package com.ideascale.commons.security

import com.ideascale.commons.security.authorization.AuthorizationDecision
import com.ideascale.commons.security.authorization.AuthorizerBuilder
import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.ActionId
import com.ideascale.commons.security.model.DenyReason
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.model.ResourceId
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyContext
import com.ideascale.commons.security.policy.PolicyEffect
import com.ideascale.commons.security.policy.dsl.policies
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private object Idea : Resource { override val id = ResourceId("Idea") }
private object Read : Action { override val id = ActionId("Read") }

private object IsAuthenticated : Policy {
  override val id: PolicyId = PolicyId("auth.isAuthenticated")
  override fun evaluate(ctx: PolicyContext): PolicyEffect =
    if (ctx.request.principal != null) PolicyEffect.Allow else PolicyEffect.NotApplicable
}

private object AlwaysAllow : Policy {
  override val id: PolicyId = PolicyId("policy.allow")
  override fun evaluate(ctx: PolicyContext): PolicyEffect = PolicyEffect.Allow
}

private object AlwaysDeny : Policy {
  override val id: PolicyId = PolicyId("policy.deny")
  override fun evaluate(ctx: PolicyContext): PolicyEffect = PolicyEffect.Deny(DenyReason("blocked"))
}

private object Throws : Policy {
  override val id: PolicyId = PolicyId("policy.throws")
  override fun evaluate(ctx: PolicyContext): PolicyEffect = error("boom")
}

class SmokeTest {
  @Test
  fun `authorizer allows authenticated read`() {
    val cfg = policies {
      resource(Idea) { action(Read) { +IsAuthenticated } }
    }
    val authz = AuthorizerBuilder(cfg).build()

    val decision = authz.authorize(
      AuthorizationRequest(
        principal = Principal(memberId = 1L, workspaceId = 10L),
        resource = Idea,
        action = Read,
        resourceId = 123L
      )
    )
    assertTrue(decision.granted)
  }

  @Test
  fun `deny overrides allow`() {
    val cfg = policies {
      resource(Idea) {
        action(Read) {
          +AlwaysAllow
          +AlwaysDeny
        }
      }
    }
    val authz = AuthorizerBuilder(cfg).build()

    val decision = authz.authorize(
      AuthorizationRequest(
        principal = Principal(memberId = 1L, workspaceId = 10L),
        resource = Idea,
        action = Read,
        resourceId = 123L
      )
    )

    assertFalse(decision.granted)
    val deny = asDeny(decision)
    assertEquals("blocked", deny.reason.code)
    assertEquals(AlwaysDeny.id, deny.decidedByPolicyId)
  }

  @Test
  fun `no allow results in default deny`() {
    val cfg = policies {
      resource(Idea) { action(Read) { +IsAuthenticated } }
    }
    val authz = AuthorizerBuilder(cfg).build()

    val decision = authz.authorize(
      AuthorizationRequest(
        principal = null,
        resource = Idea,
        action = Read,
        resourceId = 123L
      )
    )

    assertFalse(decision.granted)
    val deny = asDeny(decision)
    assertEquals("default-deny", deny.reason.code)
  }

  @Test
  fun `policy exception fails closed`() {
    val cfg = policies {
      resource(Idea) { action(Read) { +Throws } }
    }
    val authz = AuthorizerBuilder(cfg).build()

    val decision = authz.authorize(
      AuthorizationRequest(
        principal = Principal(memberId = 1L, workspaceId = 10L),
        resource = Idea,
        action = Read,
        resourceId = 123L
      )
    )

    assertFalse(decision.granted)
    val deny = asDeny(decision)
    assertEquals("exception", deny.reason.code)
    assertEquals("policy-evaluate", deny.reason.details["phase"])
    assertEquals(Throws.id.value, deny.reason.details["policyId"])
    assertEquals("java.lang.IllegalStateException", deny.reason.details["exceptionType"])
  }

  private fun asDeny(decision: AuthorizationDecision): AuthorizationDecision.Deny {
    if (decision is AuthorizationDecision.Deny) return decision
    throw AssertionError("Expected deny decision, but got: $decision")
  }
}
