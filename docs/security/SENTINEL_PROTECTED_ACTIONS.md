# Sentinel Protected Actions

Product: `sentinel-core`
Release Handling: every canonical protected action must be known to the core registry, denied under deny-all policy, denied when malformed, denied when unknown, and documented here.

| Protected Action | Release Handling |
| --- | --- |
| `agent.spawn` | Canonical protected action; fail closed unless explicitly authorized. |
| `artifact.register` | Canonical protected action; fail closed unless explicitly authorized. |
| `artifact.export` | Canonical protected action; fail closed unless explicitly authorized. |
| `artifact.use` | Canonical protected action; fail closed unless explicitly authorized. |
| `browser.navigate_external` | Canonical protected action; fail closed unless explicitly authorized. |
| `capability.issue` | Canonical protected action; fail closed unless explicitly authorized. |
| `capability.consume` | Canonical protected action; fail closed unless explicitly authorized. |
| `chat.respond` | Canonical protected action; fail closed unless explicitly authorized. |
| `effect.execute` | Canonical protected action; fail closed unless explicitly authorized. |
| `external_message.send` | Canonical protected action; fail closed unless explicitly authorized. |
| `file.delete` | Canonical protected action; fail closed unless explicitly authorized. |
| `file.read_sensitive` | Canonical protected action; fail closed unless explicitly authorized. |
| `file.write` | Canonical protected action; fail closed unless explicitly authorized. |
| `game.respond` | Canonical protected action; fail closed unless explicitly authorized. |
| `game.share` | Canonical protected action; fail closed unless explicitly authorized. |
| `hardware.activate_camera` | Canonical protected action; fail closed unless explicitly authorized. |
| `hardware.activate_microphone` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.genesis` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.register` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.rebind` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.key.register` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.key.revoke` | Canonical protected action; fail closed unless explicitly authorized. |
| `identity.key.rotate` | Canonical protected action; fail closed unless explicitly authorized. |
| `installer.update` | Canonical protected action; fail closed unless explicitly authorized. |
| `memory.write` | Canonical protected action; fail closed unless explicitly authorized. |
| `memory.delete` | Canonical protected action; fail closed unless explicitly authorized. |
| `model.generate` | Canonical protected action; fail closed unless explicitly authorized. |
| `network.egress` | Canonical protected action; fail closed unless explicitly authorized. |
| `network.request` | Canonical protected action; fail closed unless explicitly authorized. |
| `payment.or_commitment` | Canonical protected action; fail closed unless explicitly authorized. |
| `plugin.install` | Canonical protected action; fail closed unless explicitly authorized. |
| `plugin.execute` | Canonical protected action; fail closed unless explicitly authorized. |
| `policy.evaluate` | Canonical protected action; fail closed unless explicitly authorized. |
| `process.spawn` | Canonical protected action; fail closed unless explicitly authorized. |
| `profile.generate` | Canonical protected action; fail closed unless explicitly authorized. |
| `robot.command` | Canonical protected action; fail closed unless explicitly authorized. |
| `shell.execute` | Canonical protected action; fail closed unless explicitly authorized. |
| `system.install` | Canonical protected action; fail closed unless explicitly authorized. |
| `tool.invoke` | Canonical protected action; fail closed unless explicitly authorized. |
| `tool.run` | Canonical protected action; fail closed unless explicitly authorized. |

