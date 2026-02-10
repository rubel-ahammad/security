package com.ideascale.commons.security

import com.ideascale.commons.security.api.*
import kotlin.test.Test
import kotlin.test.assertTrue

private object Idea : Resource { override val id = ResourceId("Idea") }
private object Read : Action { override val id = ActionId("Read") }

private object IsAuthenticated : Policy {
  override val id: PolicyId = PolicyId("auth.isAuthenticated")
  override fun evaluate(ctx: AccessContext): PolicyEffect =
    if (ctx.request.principal != null) PolicyEffect.Allow else PolicyEffect.NotApplicable
}

class SmokeTest {
  @Test
  fun `authorizer allows authenticated read`() {
    val cfg = policies {
      resource(Idea) { action(Read) { +IsAuthenticated } }
    }
    val authz = Authorizers.from(cfg)

    val decision = authz.authorize(
      AccessRequest(
        principal = Principal(memberId = 1L, workspaceId = 10L),
        resource = Idea,
        action = Read,
        resourceId = 123L
      )
    )
    assertTrue(decision.granted)
  }
}
