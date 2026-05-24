# Pack rules reference

This file documents each detection rule in this folder and explains its core logic, inputs, and configurable settings.

## detection/packs/abuse_pack.py

- `abuse.sql_injection` (class `SqlInjectionRule`)
  - When applied: supports requests where `tool_args` is a dict.
  - Core logic: scans string-valued tool arguments for common SQL-injection patterns (OR clauses, UNION SELECT, DROP TABLE, stacked statements, `xp_cmdshell`, inline comments, etc.) using compiled regular expressions.
  - Result: returns a positive detection with severity `high` when any pattern matches, including which argument and which regex matched.

- `abuse.large_payload` (class `LargePayloadRule`)
  - When applied: evaluates every request.
  - Core logic: compares `req.payload_size_bytes` against `large_payload_threshold_bytes` (default 4096). If payload size exceeds the threshold, it flags the request.
  - Result: positive detection with severity `medium` and a message containing the sizes.
  - Tuning: adjust `large_payload_threshold_bytes` in runtime settings.

- `abuse.rapid_repeat_ip` (class `RapidRepeatIpRule`)
  - When applied: evaluates every request.
  - Core logic: uses the runtime `state` to record a timestamped request per `req.client_ip`, counts requests from that IP in the most recent `rapid_repeat_window_sec` (default 15s), and triggers if count > `rapid_repeat_limit` (default 5).
  - Result: positive detection with severity `medium` and a message including IP, count and window.
  - Tuning: change `rapid_repeat_window_sec` and `rapid_repeat_limit`.

- `abuse.reused_token_multi_ip` (class `ReusedTokenMultiIpRule`)
  - When applied: only supports requests with a non-empty `req.auth_token`.
  - Core logic: records the `(token, ip, timestamp)` in `state`, computes unique IPs that used the same token within `token_multi_ip_window_sec` (default 60s), and triggers if the number of unique IPs > `token_multi_ip_max_ips` (default 1).
  - Result: positive detection with severity `high` and a message listing the observed IPs.
  - Tuning: change `token_multi_ip_window_sec` and `token_multi_ip_max_ips`.

## detection/packs/filesystem_pack.py

- `filesystem.path_outside_allowed_base` (class `PathOutsideAllowedBaseRule`)
  - When applied: supports requests with `tool_args` dict containing a `path` entry.
  - Core logic: normalizes the provided path and the configured `allowed_base` (default `/project/data`) using POSIX normalization, and flags if the path does not equal or is not a child of the allowed base.
  - Result: positive detection with severity `high` and a message showing the offending path and allowed base.
  - Tuning: set `allowed_base` in settings.

- `filesystem.path_traversal` (class `PathTraversalRule`)
  - When applied: evaluates requests where `tool_args` is a dict.
  - Core logic: inspects each argument value as text and flags if it contains `../` or `..\\` which indicate path traversal attempts.
  - Result: positive detection with severity `high` and a message naming the argument.

- `filesystem.missing_required_args` (class `MissingRequiredArgsRule`)
  - When applied: supports requests that include `req.tool_name`.
  - Core logic: looks up `tool_schemas` from settings (a mapping of tool name → list of required arg names). If a schema exists for the invoked tool, verifies that each required argument is present in `req.tool_args`; flags when one or more are missing.
  - Result: positive detection with severity `medium` and a message listing missing arguments and the expected schema.
  - Tuning: populate `tool_schemas` in settings to enable this check for specific tools.

## detection/packs/identity_pack.py

- `identity.missing_auth_token` (class `MissingAuthTokenRule`)
  - When applied: supports requests where `req.mcp_method == "tools/call"`.
  - Core logic: checks for presence of `req.auth_token` and flags requests missing an authorization bearer token.
  - Result: positive detection with severity `low` and a short explanatory message.

## Notes & Recommendations

- All rules return a `RuleResult(id, matched, message, severity)`; consumers should use `id` and `severity` for policy decisions.
- Many rules rely on the in-memory `state` and `ctx.settings` for counting and thresholds; tune those settings system-wide (or per-pack) to fit expected traffic patterns.
- Regex-based detections (SQL) are conservative and may produce false positives on complex inputs; consider logging matched values for a short evaluation period before changing blocking behavior.

If you want, I can also:
- convert this to a pack-level README with links to the specific rule classes,
- add example config snippets for `ctx.settings` tuning, or
- generate unit tests that assert each rule's behavior.
