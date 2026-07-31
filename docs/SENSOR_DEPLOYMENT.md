# Despliegue como sensor de captura en vivo (Linux)

`network_mode: host` de Docker — necesario para que el contenedor vea tráfico real de una
interfaz de red — solo funciona de forma nativa en **Docker Engine sobre Linux** (físico o VM).
No funciona igual en **Docker Desktop (macOS/Windows)**: ahí el motor de Docker corre dentro de
una VM propia sin acceso directo a las interfaces de red del sistema anfitrión, así que
`network_mode: host` termina viendo la red interna de esa VM, no tu red física. Para
Docker Desktop, usa el flujo normal de `docker-compose.yml` (ver `README.md`) y analiza archivos
`.pcap` capturados por separado (por ejemplo con `tcpdump`/Wireshark en el propio host).

Esta guía es para cuando el objetivo es un **sensor real**, monitoreando tráfico de una red
IT/OT desde un puerto SPAN/mirror.

## Arquitectura

```
[Switch de planta] --puerto SPAN/mirror--> [NIC dedicada de captura] --> [Host Linux + Docker Engine]
                                                                                |
                                                                    TridentyOT (network_mode: host)
                                                                                |
                                                             Dashboard/API en :8000 (solo red de gestión)
```

- El host puede ser un mini-PC/NUC físico o una VM, siempre que la NIC de captura esté
  conectada directamente (bridge, no NAT) al puerto físico que recibe el mirror del switch.
- Esa NIC de captura normalmente **no necesita IP propia** — solo debe estar *up*; el modo
  promiscuo lo activa automáticamente libpcap/Scapy al iniciar la captura.
- Usa una interfaz separada (o la red de gestión existente) solo para administrar el sensor y
  acceder al dashboard — nunca la misma NIC que recibe el mirror, y nunca expuesta a internet
  (ver "Seguridad" más abajo).

## Requisitos

- Linux (cualquier distro moderna) con **Docker Engine** instalado — ver
  https://docs.docker.com/engine/install/ (no Docker Desktop).
- Usuario con acceso root o al grupo `docker`.
- El host físicamente conectado al puerto SPAN/mirror o a un TAP de red.

## Desplegar

```bash
git clone <tu-repo> && cd TridentyOT
docker compose -f docker-compose.yml -f docker-compose.linux-sensor.yml up -d --build
```

`docker-compose.linux-sensor.yml` cambia el servicio a `network_mode: host`: el contenedor pasa
a ver directamente todas las interfaces de red del host (incluida la del SPAN port), y la app
queda disponible en `http://<ip-del-host>:8000` sin necesidad de mapeo de puertos.

## Iniciar la captura en la interfaz del SPAN port

Identifica el nombre de la interfaz conectada al mirror (`ip link show` en el host, p. ej. `eth1`):

```bash
curl -X POST http://localhost:8000/api/capture/live/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth1", "bpf_filter": "ip or arp"}'
```

O desde el dashboard (`http://<ip-del-sensor>:8000`, pestaña **Captura**), eligiendo esa interfaz
de la lista.

## Persistencia y arranque

- El volumen con nombre `tridentyot_data` conserva el inventario y los hallazgos entre reinicios
  del contenedor o del host.
- `restart: unless-stopped` hace que el contenedor vuelva a levantarse solo tras un reinicio del
  host (asegúrate de que Docker arranque al boot: `sudo systemctl enable docker`).
- La sesión de captura en vivo **no se reinicia sola** al reiniciar el contenedor (a propósito:
  evita capturas fantasma si el contenedor se reinició por un error). Vuelve a llamar al endpoint
  de arriba, o automatízalo con un servicio `systemd` / cron `@reboot` que lo haga al boot.

## Seguridad (crítico en un sensor real)

TridentyOT incluye autenticación por usuario/contraseña con dos perfiles: **editor** (control
total: capturas, escaneos, edición de inventario, gestión de usuarios) y **visualizador**
(solo lectura). Al arrancar por primera vez se crea automáticamente el usuario `admin` con
contraseña `admin` y perfil editor.

- **Cambia la contraseña del usuario `admin` inmediatamente** después del primer despliegue
  (pestaña "Usuarios" del dashboard, o `PATCH /api/users/{id}`), y crea cuentas individuales
  con el perfil mínimo necesario (visualizador para quien solo necesita consultar).
- La sesión se maneja con un token bearer (expira a los 7 días por defecto, configurable con
  `TRIDENTYOT_SESSION_LIFETIME_SECONDS`); no hay integración con SSO/LDAP.
- Aun con autenticación, **no publiques el puerto 8000 en la VLAN que estás monitoreando ni en
  internet**. Restringe el acceso por firewall/ACL a una red de gestión de confianza.
- Si necesitas acceso remoto, hazlo por VPN o túnel SSH (`ssh -L 8000:localhost:8000 ...`), no por
  exposición directa.
- Si varias personas necesitan acceso al dashboard, un reverse proxy (nginx/Caddy) delante sigue
  siendo recomendable para TLS y logging adicional, aunque ya no es la única barrera de acceso.
