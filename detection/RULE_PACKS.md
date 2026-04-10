# Detection Rule Packs

This framework replaces hardcoded PoC rules with a modular registry-based engine.

## Packs
### filesystem_pack
- filesystem.path_outside_allowed_base
- filesystem.path_traversal
- filesystem.missing_required_args

### abuse_pack
- abuse.sql_injection
- abuse.large_payload
- abuse.rapid_repeat_ip
- abuse.reused_token_multi_ip

### identity_pack
- identity.missing_auth_token

## Configuration
All rules are controlled by `detection/config.yaml`.
- `packs.<pack_name>` toggles an entire pack
- `rules.<rule_id>` toggles a single rule
- `settings.*` provides shared parameters like thresholds and allowed paths

## Output contract
Rules only influence the documented fields:
- opa_policy_id
- opa_result
- opa_matched_rules
- violations[]
No custom undocumented output fields should be emitted.
