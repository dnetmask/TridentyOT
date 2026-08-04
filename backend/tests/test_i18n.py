from app.i18n import bilingual, encode_i18n, message, normalize_locale, render_i18n, resolve_locale


def test_render_i18n_picks_the_requested_locale():
    raw = encode_i18n(bilingual(es="Protocolo inseguro", en="Insecure protocol"))
    assert render_i18n(raw, "es") == "Protocolo inseguro"
    assert render_i18n(raw, "en") == "Insecure protocol"


def test_render_i18n_joins_multiple_items_with_semicolons():
    raw = encode_i18n(
        bilingual(es="primero", en="first"),
        bilingual(es="segundo", en="second"),
    )
    assert render_i18n(raw, "es") == "primero; segundo"
    assert render_i18n(raw, "en") == "first; second"


def test_render_i18n_falls_back_to_spanish_for_unsupported_locale():
    raw = encode_i18n(bilingual(es="hola", en="hello"))
    assert render_i18n(raw, "fr") == "hola"
    assert render_i18n(raw, None) == "hola"


def test_render_i18n_passes_through_legacy_plain_text_unchanged():
    """A row written before this feature existed (or third-party text, e.g.
    an NVD CVE description) isn't JSON -- must display exactly as stored,
    never raise, regardless of requested locale."""
    legacy = "Texto en español escrito antes de existir i18n."
    assert render_i18n(legacy, "en") == legacy
    assert render_i18n(legacy, "es") == legacy


def test_render_i18n_passes_through_none():
    assert render_i18n(None, "en") is None


def test_message_looks_up_by_key_and_locale():
    assert message("auth.invalid_credentials", "es") == "Usuario o contraseña incorrectos"
    assert message("auth.invalid_credentials", "en") == "Incorrect username or password"


def test_normalize_locale_handles_tags_and_accept_language_headers():
    assert normalize_locale("en") == "en"
    assert normalize_locale("en-US") == "en"
    assert normalize_locale("es_MX") == "es"
    assert normalize_locale("en-US,en;q=0.9,es;q=0.8") == "en"
    assert normalize_locale("fr") == "es"  # unsupported -> default
    assert normalize_locale(None) == "es"


def test_resolve_locale_prefers_stored_user_preference_over_header():
    assert resolve_locale("en", "es-ES") == "en"
    assert resolve_locale(None, "en-US") == "en"
    assert resolve_locale(None, None) == "es"


def test_user_can_change_own_locale(client):
    assert client.get("/api/auth/me").json()["locale"] == "es"

    resp = client.patch("/api/auth/me", json={"locale": "en"})
    assert resp.status_code == 200
    assert resp.json()["locale"] == "en"
    assert client.get("/api/auth/me").json()["locale"] == "en"


def test_viewer_can_change_their_own_locale_even_though_not_an_admin(client, make_client):
    create_resp = client.post("/api/users", json={"username": "vwr", "password": "vwrpass1", "role": "viewer"})
    assert create_resp.status_code == 201

    viewer = make_client("vwr", "vwrpass1")
    resp = viewer.patch("/api/auth/me", json={"locale": "en"})
    assert resp.status_code == 200
    assert resp.json()["locale"] == "en"


def test_login_error_language_follows_accept_language_header(anonymous_client):
    resp_es = anonymous_client.post(
        "/api/auth/login",
        json={"username": "nobody", "password": "wrong"},
        headers={"Accept-Language": "es"},
    )
    resp_en = anonymous_client.post(
        "/api/auth/login",
        json={"username": "nobody", "password": "wrong"},
        headers={"Accept-Language": "en-US,en;q=0.9"},
    )
    assert resp_es.json()["detail"] == "Usuario o contraseña incorrectos"
    assert resp_en.json()["detail"] == "Incorrect username or password"


def test_findings_are_rendered_in_the_caller_s_locale(client, tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    syn = Ether() / IP(src="10.0.9.5", dst="10.0.9.100", ttl=64) / TCP(
        sport=41000, dport=23, flags="S", window=1024
    )
    pcap_path = tmp_path / "telnet.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("telnet.pcap", f, "application/vnd.tcpdump.pcap")})

    findings_es = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    telnet_es = next(f for f in findings_es if "telnet" in f["rule_id"])
    assert "inseguro" in telnet_es["title"].lower()

    client.patch("/api/auth/me", json={"locale": "en"})
    findings_en = client.get("/api/vuln/findings").json()
    telnet_en = next(f for f in findings_en if "telnet" in f["rule_id"])
    assert "insecure" in telnet_en["title"].lower()
