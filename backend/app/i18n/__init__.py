"""Two-language (es/en) support for text that reaches a human: HTTP-facing
messages and the evidence/title/description text the fingerprinting and
vulnerability engines generate.

Two different mechanisms, picked per use case:

- `MESSAGES` / `message()`: a keyed registry for strings that recur
  verbatim across the app (auth errors, "not found", ...). Looked up by a
  stable key, e.g. "auth.invalid_credentials".
- `bilingual()` / `encode_i18n()` / `render_i18n()`: for text built at
  detection time with interpolated values (an evidence sentence naming a
  specific protocol/port/vendor). Rather than a keyed template + params,
  the call site simply writes both language versions inline
  (`bilingual(es="...", en="...")`) and `encode_i18n()` serializes them to
  JSON for storage in a Text column. `render_i18n()` renders that JSON back
  to plain text in the requested locale at read time.

This keeps translation a display-time concern: the DB stores the bilingual
JSON once, and every reader (any locale, now or after a user changes their
preference) gets the right language without re-running detection.

A value that predates this feature -- or NVD's own English CVE
descriptions, which are never translated -- isn't valid "our" JSON and
`render_i18n()` returns it unchanged instead of raising, so old rows and
third-party text keep displaying exactly as before.
"""

import json
from typing import Any

SUPPORTED_LOCALES = ("es", "en")
DEFAULT_LOCALE = "es"


def normalize_locale(locale: str | None) -> str:
    """Accepts a plain locale ("en"), a locale tag ("en-US", "es_MX"), or a
    full Accept-Language header ("en-US,en;q=0.9,es;q=0.8") and reduces it
    to one of SUPPORTED_LOCALES, defaulting to DEFAULT_LOCALE for anything
    else (missing, unsupported, malformed)."""
    if not locale:
        return DEFAULT_LOCALE
    primary = locale.split(",")[0].strip().split("-")[0].split("_")[0].lower()
    return primary if primary in SUPPORTED_LOCALES else DEFAULT_LOCALE


def resolve_locale(user_locale: str | None, accept_language: str | None = None) -> str:
    """A logged-in user's stored preference always wins; an anonymous
    request (e.g. the 401 a bad login attempt returns, before there's any
    user to read a preference from) falls back to its Accept-Language
    header, then to DEFAULT_LOCALE."""
    if user_locale:
        return normalize_locale(user_locale)
    return normalize_locale(accept_language)


# ---------------------------------------------------------------------------
# Keyed registry -- reusable HTTP-facing strings
# ---------------------------------------------------------------------------

MESSAGES: dict[str, dict[str, str]] = {
    "auth.not_authenticated": {"es": "No autenticado", "en": "Not authenticated"},
    "auth.invalid_session": {"es": "Sesión inválida", "en": "Invalid session"},
    "auth.session_expired": {
        "es": "Sesión expirada, vuelve a iniciar sesión",
        "en": "Session expired, please log in again",
    },
    "auth.admin_required": {
        "es": "Esta acción requiere el perfil de administrador",
        "en": "This action requires the administrator role",
    },
    "auth.super_admin_required": {
        "es": "Esta acción requiere el perfil de Super Admin",
        "en": "This action requires the Super Admin role",
    },
    "auth.invalid_credentials": {
        "es": "Usuario o contraseña incorrectos",
        "en": "Incorrect username or password",
    },
    "users.duplicate_username": {
        "es": "Ya existe un usuario con ese nombre",
        "en": "A user with that name already exists",
    },
    "users.not_found": {"es": "Usuario no encontrado", "en": "User not found"},
    "users.super_admin_has_no_organization": {
        "es": "Un Super Admin no tiene organización propia para crear usuarios en ella",
        "en": "A Super Admin has no organization of its own to create users in",
    },
    "users.cannot_remove_last_admin_role": {
        "es": "No puedes quitar el rol de administrador: no quedaría ningún administrador en la organización",
        "en": "You can't remove the administrator role: no administrator would remain in the organization",
    },
    "users.cannot_delete_self": {
        "es": "No puedes eliminar tu propio usuario",
        "en": "You can't delete your own user",
    },
    "users.cannot_delete_last_admin": {
        "es": "No puedes eliminar el último administrador de la organización",
        "en": "You can't delete the last administrator in the organization",
    },
    "capture.session_not_found": {
        "es": "Sesión de captura no encontrada",
        "en": "Capture session not found",
    },
    "capture.not_a_live_session": {
        "es": "La sesión no es una captura en vivo",
        "en": "Session is not a live capture",
    },
    "inventory.device_not_found": {"es": "Dispositivo no encontrado", "en": "Device not found"},
    "organizations.duplicate_slug": {
        "es": "Ya existe una organización con ese identificador",
        "en": "An organization with that slug already exists",
    },
    "organizations.not_found": {"es": "Organización no encontrada", "en": "Organization not found"},
    "sites.not_found": {"es": "Sitio no encontrado", "en": "Site not found"},
    "sites.organization_id_required": {
        "es": "Debes indicar la organización para este sitio",
        "en": "You must specify the organization for this site",
    },
    "zones.not_found": {"es": "Zona no encontrada", "en": "Zone not found"},
    "sensors.not_found": {"es": "Sensor no encontrado", "en": "Sensor not found"},
}


def message(key: str, locale: str | None) -> str:
    entry = MESSAGES.get(key)
    if entry is None:
        return key
    loc = normalize_locale(locale)
    return entry.get(loc) or entry.get(DEFAULT_LOCALE) or key


# ---------------------------------------------------------------------------
# Inline bilingual content -- evidence / title / description text
# ---------------------------------------------------------------------------


def bilingual(es: str, en: str) -> dict[str, str]:
    return {"es": es, "en": en}


def encode_i18n(*items: Any) -> str:
    """Serializes one or more bilingual()/plain-string items (or lists of
    them) produced at detection time into the JSON stored in a Text column.
    A single item is stored as itself, not wrapped in a one-element list,
    so the common case (one evidence sentence) round-trips as a plain
    JSON object rather than an array of one."""
    flat: list[Any] = []
    for item in items:
        if isinstance(item, list):
            flat.extend(item)
        elif item is not None:
            flat.append(item)
    if not flat:
        return json.dumps(None)
    if len(flat) == 1:
        return json.dumps(flat[0], ensure_ascii=False)
    return json.dumps(flat, ensure_ascii=False)


def _render_node(data: Any, loc: str) -> str:
    if isinstance(data, dict) and ("es" in data or "en" in data):
        return data.get(loc) or data.get(DEFAULT_LOCALE) or ""
    if isinstance(data, list):
        return "; ".join(part for part in (_render_node(item, loc) for item in data) if part)
    if isinstance(data, str):
        return data
    return ""


def render_i18n(raw: str | None, locale: str | None) -> str | None:
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return raw  # legacy plain text, or third-party text (e.g. NVD's English CVE descriptions)
    if data is None:
        return None
    loc = normalize_locale(locale)
    rendered = _render_node(data, loc)
    return rendered if rendered else raw
