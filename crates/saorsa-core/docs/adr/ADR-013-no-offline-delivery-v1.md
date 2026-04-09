# ADR-013: No Offline Message Delivery (v1)

## Status

Accepted (with future reconsideration)

## Context

Messaging systems typically support offline message delivery, allowing messages to be stored and delivered when recipients come online. Common approaches include:

### Traditional Messaging (Email, SMS)
- **Email**: Messages stored for 30+ days on mail servers
- **SMS**: Messages stored for 24-48 hours on carrier networks
- **Pros**: Reliable asynchronous communication
- **Cons**: Requires centralized storage infrastructure, privacy concerns, message retention policies

### P2P Messaging with Store-and-Forward
- Messages stored on relay nodes or DHT for extended periods
- **Pros**: Asynchronous communication, better UX for offline users
- **Cons**:
  - Increased storage requirements on network nodes
  - Longer message retention = greater privacy risk
  - Complexity in managing message lifecycle
  - Need for cleanup policies and storage quotas

### DHT-Based Short TTL (Current Saorsa Approach)
- Messages stored in DHT with 1-hour (3600 second) TTL
- **Pros**:
  - Privacy-preserving (messages expire quickly)
  - Reduced storage burden on DHT nodes
  - Simple architecture
- **Cons**:
  - Messages lost if recipient offline > 1 hour
  - May not suit asynchronous communication patterns

## Decision

**For v1 of Saorsa messaging, we will NOT implement offline message delivery beyond the existing 1-hour DHT TTL.**

### Rationale

1. **Privacy First**: Short message retention (1 hour) minimizes data exposure
2. **Simplicity**: Avoid complexity of long-term storage orchestration
3. **DHT Efficiency**: Current K=8 replication is sustainable for 1-hour TTL
4. **Alignment with Real-Time Use**: Saorsa prioritizes real-time collaboration
5. **Deferred Decision**: Can add later based on user feedback

### What This Means

- **Maximum offline window**: 1 hour (3600 seconds)
- **Message delivery guarantee**: Best-effort within DHT TTL
- **After TTL expiration**: Messages permanently removed from DHT
- **User expectation**: Recipients should be online within 1 hour to receive messages
- **Queueing behavior**: Messages queue for retry but expire after TTL

## Consequences

### Positive

✅ **Privacy-Preserving**: Messages don't persist indefinitely in the network
✅ **Simple Architecture**: No need for long-term storage coordination
✅ **Reduced Storage Load**: DHT nodes only store messages for 1 hour
✅ **Clear Expectations**: Users understand real-time communication model
✅ **Lower Attack Surface**: Less time for adversaries to intercept stored messages

### Negative

⚠️ **Messages Lost if Offline > 1 Hour**: Recipients must come online within TTL
⚠️ **Different from Traditional Messaging**: Users accustomed to email/SMS may expect longer retention
⚠️ **Asynchronous Workflows Limited**: May not suit all collaboration patterns
⚠️ **No Delivery Receipts for Expired Messages**: Senders may not know message was lost

### Mitigation Strategies

For users who need asynchronous communication:
1. **External Persistence**: Applications can implement local message queues
2. **Notification Systems**: Out-of-band notifications (email, push) to prompt online presence
3. **Channel-Based Persistence**: Channels could store message history (separate from transport layer)

## Future Considerations

This decision is **not permanent**. We will reconsider offline message delivery if:

1. **User Feedback**: Users consistently report need for longer offline windows
2. **Use Case Evolution**: Saorsa expands beyond real-time collaboration
3. **Technical Advances**: Better privacy-preserving storage solutions emerge
4. **Storage Economics**: DHT storage becomes cheaper/more efficient

### Potential Future Approaches

If we implement offline delivery later, candidate solutions include:

1. **Configurable TTL**: Allow users/channels to set TTL (1 hour - 7 days)
2. **Mailbox Nodes**: Dedicated nodes for offline storage (opt-in)
3. **Encrypted Relay**: Store encrypted messages on recipient's designated nodes
4. **Retention Policies**: Apply explicit retention and garbage-collection policies per topic

## Related ADRs

- **ADR-001**: Multi-Layer P2P Architecture (DHT storage layer)
- **ADR-005**: S/Kademlia Witness Protocol (DHT reliability)
- **ADR-003**: Pure Post-Quantum Crypto (message encryption)

## References

- Phase 2 Task 2: DHT Storage Analysis (`.planning/architecture-analysis/02-dht-storage.md`)
- DHT TTL Configuration: `src/placement/dht_records.rs:97` (DEFAULT_TTL = 3600s)
- Message Queueing: Removed with the user messaging subsystem (out of scope for this ADR)

## Decision Date

2026-01-29

## Decision Makers

- Architecture Team (via Phase 2 analysis)
- Product Direction: Real-time collaboration focus
