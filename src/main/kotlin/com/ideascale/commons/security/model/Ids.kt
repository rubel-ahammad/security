package com.ideascale.commons.security.model

@JvmInline
value class PolicyId(val value: String) {
  override fun toString(): String = value
}

@JvmInline
value class ResourceId(val value: String) {
  override fun toString(): String = value
}

@JvmInline
value class ActionId(val value: String) {
  override fun toString(): String = value
}
