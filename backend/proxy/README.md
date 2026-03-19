# Proxy

This module is the live traffic surface of the system.

## Planned internal areas

- `addons/` - mitmproxy add-ons and integration hooks.
- `capture/` - capture sessions and raw flow collection.
- `normalization/` - normalized request and response models.
- `redaction/` - secret, token, and sensitive field handling.
- `replay/` - controlled replay preparation and request reconstruction.

The proxy engine exists to make live API behavior visible to the audit system without mixing traffic handling into the API server.
