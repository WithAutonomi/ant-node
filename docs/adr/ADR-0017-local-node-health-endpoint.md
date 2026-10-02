# ADR-0017: Local node health endpoint

- **Status:** Proposed
- **Date:** 2026-09-30
- **Decision owners:** ant-node maintainers (review pending)
- **Reviewers:** Jim Collinson; ant-node maintainers (review pending)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [V2-1380](https://linear.app/autonominetwork/issue/V2-1380/ant-node-serve-a-local-health-endpoint-on-the-existing-metrics-port)

## Context

The node already holds information about its connectivity, storage and uptime,
but local tools cannot ask for it. Its configuration advertises a monitoring
endpoint that has not served anything. Operators and applications instead see
only process state or must inspect logs. Logging is optional, and its messages
are not a stable interface.

Starting a listener on existing nodes could conflict with other local services.
Ordinary deployments should remain unchanged unless an operator enables it.

## Decision Drivers

- Make existing state available without requiring logging or new instrumentation.
- Support people, applications and standard monitoring tools.
- Keep the node private, dependency-light and unaffected by diagnostic failures.
- Require an explicit choice to enable the service.

## Considered Options

1. **Read logs:** rejected because messages change and logging may be disabled.
2. **Use a private channel through the management daemon:** rejected because it
   couples the node to one consumer and requires a larger coordinated change.
3. **Let the node answer local, read-only health queries:** chosen because each
   consumer can ask directly for the existing state.

## Decision

The node will offer its own health information on demand through a local endpoint.
We commit to these boundaries:

- It binds only to loopback, meaning it is reachable only on the same machine.
- It is read-only and discloses no secrets, network addresses or filesystem paths.
- A form for programs and a form for monitoring carry the same values.
- Its failures cannot fail node startup, and its work cannot hold shutdown open
  indefinitely.
- It advertises its bound port locally for tools to discover.
- It is off unless explicitly configured on; configuration changes apply at restart.

The concrete interface and compatibility contract belong in the README and
linked issue's specification, not in this decision record.

## Consequences

### Positive

- Local consumers obtain health without inspecting logs or storage files.
- Existing in-memory state is reused without adding dependencies.
- Nodes that do not enable the endpoint open no new listener.

### Negative / Trade-offs

- Any local process can read the published health when enabled.
- A busy port leaves that node without the endpoint rather than preventing startup.
- Remote monitoring needs a separate, deliberately configured access route.

### Neutral / Operational

- Discovery identifies where to ask, not proof that a node is healthy.
- The initial information set is intentionally limited; more instrumentation is
  separate work.

## Validation

Tests and a development-network run check both representations, disabled mode,
port conflicts, local discovery and shutdown. Review confirms local-only binding,
absence of sensitive information, and isolation from node operation.

## Notes for AI-assisted work

AI tools may draft this record but must not mark it Accepted. Human engineering
review owns acceptance; Accepted records are immutable.
