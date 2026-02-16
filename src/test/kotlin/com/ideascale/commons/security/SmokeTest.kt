package com.ideascale.commons.security

import com.ideascale.commons.security.authorization.AuthorizerBuilder
import com.ideascale.commons.security.model.AuthorizationRequest
import com.ideascale.commons.security.model.Action
import com.ideascale.commons.security.model.ActionId
import com.ideascale.commons.security.model.PolicyId
import com.ideascale.commons.security.model.Principal
import com.ideascale.commons.security.model.Resource
import com.ideascale.commons.security.model.ResourceId
import com.ideascale.commons.security.policy.Policy
import com.ideascale.commons.security.policy.PolicyContext
import com.ideascale.commons.security.policy.PolicyEffect
import com.ideascale.commons.security.policy.dsl.policies
import kotlin.test.Test
import kotlin.test.assertTrue

private object Idea : Resource { override val id = ResourceId("Idea") }
private object Read : Action { override val id = ActionId("Read") }

private object IsAuthenticated : Policy {
  override val id: PolicyId = PolicyId("auth.isAuthenticated")
  override fun evaluate(ctx: PolicyContext): PolicyEffect =
    if (ctx.request.principal != null) PolicyEffect.Allow else PolicyEffect.NotApplicable
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
}
