# Security Policy

## Scope

This repository contains a PX4 SITL security simulation and monitoring stand.
It is not a certified flight-safety or production security product.

## Supported Branch

Security fixes are prepared for the `main` branch.

## Reporting

Do not publish exploitable details in a public issue before the maintainer has
had time to review them.

Report security issues to the repository maintainer through a private GitHub
security advisory when available. If private advisories are unavailable for the
repository, contact the maintainer directly through GitHub.

## Operational Notes

- Keep `gateway_enforce=true` for defensive test runs that should block mission,
  parameter and `SERIAL_CONTROL` writes.
- Keep `authorized_client_hosts` restricted to trusted hosts. The value `"*"`
  should be used only in isolated lab networks.
- Set `siem_url` or `DRONE_SEC_SIM_SIEM_URL` only to trusted HTTP endpoints.
- Keep `mavlink_encryption_key_hex` or `DRONE_SEC_SIM_MAVLINK_KEY_HEX` outside
  public commits. Use `require_encrypted_clients=true` only with clients that
  support the repository's encrypted datagram wrapper.
- Store only SHA-256 operator token hashes in `operator_token_hashes`. Use
  `require_operator_auth=true` only with clients that support the authenticated
  encrypted datagram wrapper.
- Verify JSONL audit logs with `make verify-smoke-logs` or
  `tools/verify_audit_log.py`.

## Known Limits

- Native QGroundControl/PX4 MAVLink encryption is not implemented here. The
  repository implements an optional AES-GCM encrypted datagram wrapper at the
  gateway boundary; clients must use that wrapper to interoperate with
  `require_encrypted_clients=true`.
- Operator authentication is implemented at the repository gateway wrapper
  boundary. The repository does not implement a multi-user web UI, password
  rotation workflow, or native QGroundControl operator login integration.
- Real hardware validation requires a completed `validation/hardware_validation.json`
  created after physical-platform testing.
