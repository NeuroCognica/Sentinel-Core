# Sentinel Canon

## First Law

Let there be no gate before the Sentinel.

This is not a slogan. It is an execution invariant.

Every protected action must first enter the Sentinel boundary as a canonical envelope. The envelope verifier, nonce guard, identity proof, policy evaluator, consent recorder, capability checker, and audit ledger are all part of the Sentinel boundary. Product auth, UI checks, schedulers, planners, routers, model prompts, game state, and convenience APIs may exist only after Sentinel has seen the action and produced a decision.

## Meaning

No NeuroCognica product may execute a protected action through a route that Sentinel cannot observe, digest, evaluate, and record.

No upstream product gate may hide a protected action from Sentinel.

No product-local allowlist may substitute for Sentinel policy.

No missing policy may imply allow.

No failed Sentinel call may degrade into execution.

No denial may create a job, artifact, tool call, network call, file mutation, model output, or irreversible side effect.

## Protected Actions

At minimum, these action classes are protected:

- `chat.respond`
- `model.generate`
- `tool.run`
- `shell.execute`
- `file.write`
- `file.delete`
- `network.request`
- `artifact.register`
- `artifact.use`
- `artifact.export`
- `capability.issue`
- `capability.consume`
- `agent.spawn`
- `memory.write`
- `profile.generate`
- `game.share`
- `robot.command`

## Required Proof

A protected action is valid only when the ledger proves:

1. The request entered as a canonical envelope.
2. The envelope digest matched the exact method, path, nonce, and body.
3. The nonce was unused and consumed.
4. The actor identity and key were valid for the action.
5. An explicit policy was evaluated.
6. Consent or denial was recorded.
7. Any capability was bound to the exact artifact or resource.
8. Any effect occurred only after allow-class authorization.

## Fail Closed

If Sentinel cannot parse, verify, evaluate, append, seal, or replay the action, the action is denied.

The only acceptable failure mode for protected action ambiguity is no side effect.

## Test Bar

The proof bar is handler-level.

Unit tests are not enough. For every protected route, tests must prove that denied or malformed requests:

- return a denial or forbidden-class response,
- append an auditable denial where applicable,
- spawn no job,
- write no artifact,
- consume no capability,
- execute no effect.

Helper-only tests do not satisfy this canon.

## Integration Rule

Chronos, Sophia, Archetypes, AURA, Mecha, and any future NeuroCognica surface must integrate through a shared SentinelGuard contract.

The product may ask Sentinel for a decision. It may not decide whether Sentinel should be asked.
