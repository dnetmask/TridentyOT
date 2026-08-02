# TridentyOT

Inventario de activos de red y análisis de vulnerabilidades a partir de **captura pasiva de
tráfico** (la misma tecnología que usan `tcpdump`/`wireshark`/`tshark`), pensado para entornos
mixtos IT/OT (ICS/SCADA).

La aplicación escucha tráfico en una interfaz de red (típicamente un puerto SPAN/mirror de un
switch, o una interfaz conectada al segmento a inspeccionar) o analiza un archivo `.pcap`/`.pcapng`
ya capturado, y a partir de eso construye:

1. **Inventario de dispositivos**: IP, MAC, primer/último visto, más **nombre y fabricante**:
   - Nombre auto-detectado desde tráfico DHCP (opción 12, Host Name), respuestas DNS/mDNS tipo A,
     auto-anuncios NetBIOS/SMB (NBNS Name Registration, el servicio "Computer Browser" de
     Windows/Samba, y el *Calling Name* del handshake NetBIOS Session Service en TCP/139) y, para
     switches/routers, CDP y LLDP; si no se detecta queda en blanco. Un nombre de grupo/dominio
     NetBIOS (p. ej. "WORKGROUP") nunca se muestra como el nombre propio de un equipo.
   - Fabricante auto-detectado por MAC (OUI) contra la base real de IEEE/Wireshark (~40k prefijos).
   - Switches/routers identificados solo por CDP/LLDP (sin tráfico IP propio en el segmento
     capturado) se inventarían igual, quedan marcados como **Network appliance** y se fusionan
     automáticamente con su registro por IP si luego se les ve tráfico IP con la misma MAC.
   - Solo se listan activos de **la propia red local** (IP privada/link-local, o sin IP para un
     equipo identificado solo por MAC vía CDP/LLDP): un host con IP pública nunca aparece como
     activo del inventario, aunque las conversaciones hacia él y sus hallazgos de vulnerabilidad
     siguen visibles en **Flujos** y **Vulnerabilidades** (`GET /api/inventory/devices` acepta
     `?include_public=true` para listarlo también ahí).
   - Todo es **editable manualmente** en cualquier momento (se detecte o no), sin perder el
     valor auto-detectado como referencia.
   - **Tipo de dispositivo** (columna **Tipo**): clasifica cada activo como **PLC**, **Servidor**,
     **PC** o **Equipo de red** combinando, con reglas explicables (no ML), la evidencia que el
     resto del motor pasivo ya recolectó -- protocolo servido (un protocolo OT como servidor es
     PLC casi con certeza), anuncio CDP/LLDP (equipo de red con certeza), categoría del
     fabricante por OUI (industrial/redes/IT genérico), palabras clave del nombre del equipo
     ("-HMI01", "-SRV", "-PC"...) y cantidad de protocolos distintos servidos. Cada clasificación
     muestra su **evidencia** y una confianza 0-100%; los indicadores superiores de Inventario
     cuentan PLC/Servidores/Otros. Igual que nombre y fabricante, es **editable manualmente**
     sin perder el valor auto-detectado. Ver "Limitaciones conocidas" para el caso que esto
     no puede resolver de forma pasiva (servidor vs. PC Windows).
2. **Fingerprint pasivo de sistema operativo**: heurística basada en TTL inicial, tamaño de
   ventana TCP y opciones TCP del handshake (similar a p0f), sin enviar ningún tráfico activo.
3. **Detección de protocolos/servicios**: por puerto conocido y por firma de los primeros bytes
   del payload (HTTP, TLS, SSH, FTP...), cubriendo tanto protocolos IT comunes como protocolos
   OT/ICS (Modbus, DNP3, S7comm, EtherNet/IP, BACnet, IEC-104, OPC UA, etc.).
4. **Flujos / conversaciones**: qué par de dispositivos conversó, por qué protocolo/puerto y
   cuántos paquetes, agregado desde las sesiones TCP/UDP observadas (pestaña **Flujos**).
5. **Motor de vulnerabilidades**:
   - **Reglas locales** (sin conexión a internet): protocolos inseguros por diseño (Telnet, FTP,
     SNMP, SMB sin verificar SMBv1, etc.), exposición de protocolos OT sin autenticación/cifrado,
     y notas sobre dispositivos con pila de red embebida (posibles PLC/RTU).
   - **Consulta a NVD** (CVE 2.0 REST API): cuando se identifica un producto/versión concreto a
     partir de un banner de servicio (p. ej. `OpenSSH_7.2`, `vsFTPd 2.3.4`), se buscan CVEs
     asociados. Los resultados se cachean en base de datos porque la API pública de NVD tiene un
     límite de tasa bajo (5 solicitudes/30s sin API key) y para seguir funcionando (desde caché)
     en redes OT sin salida a internet.
   - Cada hallazgo muestra el nombre del equipo afectado (auto-detectado o manual), no solo su IP.
6. **Usuarios y control de acceso**: login con usuario/contraseña, dos perfiles —**editor**
   (control total) y **visualizador** (solo lectura)—. Al primer arranque se crea el usuario
   `admin`/`admin` (perfil editor); cámbialo cuanto antes desde la pestaña **Usuarios**.

## Estructura

```
docker-compose.yml              despliegue de un solo servicio, con volumen persistente
docker-compose.linux-sensor.yml override: network_mode host, para sensor real (ver docs/)
docs/
  SENSOR_DEPLOYMENT.md          despliegue como sensor en un host Linux + puerto SPAN/mirror
backend/
  Dockerfile         imagen de la app (Python 3.11 + FastAPI + Scapy + libpcap/tcpdump)
  app/
    capture/        captura en vivo (scapy AsyncSniffer) y carga de archivos pcap
    fingerprint/     fingerprint de SO, protocolos, hostname (DHCP/DNS/mDNS/NBNS/SMB/CDP/LLDP) y fabricante (OUI)
    inventory/       inventario de dispositivos/servicios y agregación de flujos TCP/UDP
    vuln/            reglas locales + cliente NVD + motor de escaneo
    api/             endpoints FastAPI
    static/          dashboard web (HTML/JS, sin build step)
    models.py        modelos SQLAlchemy (SQLite por defecto)
  tests/             pytest (paquetes sintéticos con scapy, sin necesidad de red real)
```

## Requisitos

- Python 3.11+
- Para **captura en vivo**: privilegios de captura raw (root, o `CAP_NET_RAW`/`CAP_NET_ADMIN` en
  Linux vía `setcap` sobre el intérprete de Python) y libpcap instalado en el sistema.
- Para **análisis de archivos .pcap**: ningún privilegio especial.

## Instalación y ejecución

### Opción A: Python + uvicorn (desarrollo)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Abre `http://localhost:8000` para el dashboard. La documentación interactiva de la API está en
`http://localhost:8000/docs`.

### Opción B: Docker Compose (recomendado para desplegar)

```bash
docker compose up -d --build
```

Esto construye la imagen desde `backend/Dockerfile` (Python 3.11 + FastAPI + Scapy + libpcap/tcpdump)
y publica el dashboard/API en `http://localhost:8000`. La base de datos SQLite y los archivos
`.pcap` subidos quedan en el volumen con nombre `tridentyot_data`, por lo que sobreviven a
`docker compose down` y a reinicios del contenedor (verificado: los dispositivos y hallazgos siguen
ahí después de un `docker restart`).

```bash
docker compose logs -f tridentyot   # ver logs
docker compose down                 # detener (agrega -v para borrar también los datos persistidos)
```

Variables de entorno (ver tabla más abajo) se definen en `docker-compose.yml` bajo `environment:`,
o en un archivo `.env` junto a él (por ejemplo `NVD_API_KEY=...`, leído automáticamente por
Docker Compose).

#### Captura en vivo dentro de Docker

Por defecto el contenedor corre en la red *bridge* de Docker, así que solo ve su propia interfaz
virtual, no las interfaces reales del host. El **análisis de archivos `.pcap` subidos funciona
igual en cualquier modo de red y en cualquier sistema operativo**, sin cambios.

Para escuchar tráfico real (un puerto SPAN/mirror, por ejemplo) el contenedor necesita
`network_mode: host`, incluido ya en el override `docker-compose.linux-sensor.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.linux-sensor.yml up -d --build
```

> **Importante — Docker Desktop (macOS/Windows):** `network_mode: host` **no** da acceso a las
> interfaces de red reales de tu Mac/Windows con Docker Desktop, porque su motor corre dentro de
> una VM propia con su propia red interna — el contenedor vería la red de esa VM, no tu Wi-Fi/
> Ethernet físico. En Mac/Windows con Docker Desktop, la única forma práctica de "capturar en
> vivo" es capturar con herramientas nativas del SO (`tcpdump`/Wireshark) y subir el `.pcap`
> resultante al dashboard. `network_mode: host` sí funciona de forma nativa en **Docker Engine
> sobre Linux** (físico o VM) — ver [`docs/SENSOR_DEPLOYMENT.md`](docs/SENSOR_DEPLOYMENT.md) para
> el despliegue completo como sensor conectado a un puerto SPAN/mirror, incluyendo
> recomendaciones de seguridad y gestión de usuarios.

El servicio ya incluye `cap_add: [NET_RAW, NET_ADMIN]` en `docker-compose.yml`, necesario para que
Scapy pueda abrir sockets raw sea cual sea el modo de red usado.

**Flujo en Docker Desktop (macOS/Windows) con `tcpdump`/Wireshark nativo del SO:**

```bash
# 1) levanta TridentyOT normalmente (Opción B de arriba)
docker compose up -d --build

# 2) captura tráfico real con herramientas nativas de macOS (fuera de Docker)
sudo tcpdump -i en0 -w captura.pcap        # Ctrl+C para detener
#   (en Windows: usa Wireshark y exporta como .pcap/.pcapng)

# 3) sube la captura a TridentyOT para análisis
curl -F "file=@captura.pcap" http://localhost:8000/api/capture/pcap
```

`en0` suele ser el Wi-Fi en Mac (`networksetup -listallhardwareports` para confirmar el nombre).

### Captura en vivo sin Docker

Requiere privilegios de captura. Dos formas típicas de darlos sin correr todo como root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

o ejecutar `uvicorn` con `sudo`. Desde el dashboard (pestaña **Captura**), o vía API:

```bash
curl -X POST http://localhost:8000/api/capture/live/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "bpf_filter": "ip or arp"}'
```

#### Cómo procesa la captura en vivo

La lectura del cable y la escritura en base de datos corren en **hilos separados, conectados por
una cola**: el hilo de Scapy solo diseca cada paquete (CPU pura) y lo encola; un hilo consumidor
aparte drena la cola por lotes (hasta 500 paquetes o 200ms, lo que ocurra primero) y hace **una
sola transacción de base de datos por lote**, en vez de una por paquete. Si el consumidor no da
abasto y la cola (acotada a 20.000 elementos) se llena, los paquetes de más se descartan mientras
se cuentan -- nunca en silencio -- en `dropped_count` de la sesión de captura (visible por API en
`GET /api/capture/sessions/{id}`). Un `dropped_count` que crece de forma sostenida es la señal de
que el segmento capturado tiene más tráfico del que este proceso puede ingerir en tiempo real.

### Analizar un archivo .pcap existente

Desde el dashboard (pestaña **Captura**) puedes arrastrar y soltar el archivo directamente sobre
la zona de carga, o hacer clic para seleccionarlo. Por API:

```bash
curl -F "file=@captura.pcap" http://localhost:8000/api/capture/pcap
```

### Ejecutar el escaneo de vulnerabilidades

```bash
curl -X POST http://localhost:8000/api/vuln/scan \
  -H "Content-Type: application/json" \
  -d '{"use_nvd": true}'
```

`use_nvd: false` limita el escaneo a las reglas locales (sin salir a internet).

## Configuración (variables de entorno)

| Variable | Descripción | Default |
|---|---|---|
| `TRIDENTYOT_DATA_DIR` | Directorio de datos (DB SQLite, archivos pcap subidos) | `backend/data` |
| `TRIDENTYOT_DATABASE_URL` | URL de SQLAlchemy (soporta Postgres, etc.) | SQLite en `TRIDENTYOT_DATA_DIR` |
| `NVD_API_KEY` | API key de NVD (opcional, sube el límite de tasa a 50 req/30s) | — |
| `NVD_CACHE_TTL_SECONDS` | Tiempo de vida del caché de resultados de NVD | 86400 (24h) |
| `TRIDENTYOT_DEFAULT_FILTER` | Filtro BPF por defecto para captura en vivo | `ip or arp` |
| `TRIDENTYOT_SESSION_LIFETIME_SECONDS` | Duración del token de sesión antes de expirar | 604800 (7 días) |
| `TRIDENTYOT_DEFAULT_ADMIN_USERNAME` | Usuario admin creado en el primer arranque (si no hay usuarios) | `admin` |
| `TRIDENTYOT_DEFAULT_ADMIN_PASSWORD` | Contraseña de ese admin inicial — **cámbiala tras el primer login** | `admin` |

## Actualizar una instalación existente

Al iniciar, la app agrega automáticamente a la base de datos cualquier columna nueva que una
versión más reciente del código haya introducido (por ejemplo, `custom_name`/`vendor` en
dispositivos), sin borrar ni tocar los datos ya existentes. Basta con actualizar el código
(`git pull` / reconstruir la imagen Docker) y reiniciar — no hace falta borrar la base de datos.
Esto cubre columnas nuevas, que es como ha evolucionado el esquema hasta ahora; un cambio más
profundo (renombrar o eliminar una columna) sí requeriría una migración manual.

## Tests

```bash
cd backend
source .venv/bin/activate
python -m pytest
```

Los tests construyen paquetes sintéticos con scapy y archivos `.pcap` temporales, por lo que no
requieren acceso a una red real ni privilegios especiales; las pruebas relacionadas con NVD usan
un doble (mock) del cliente HTTP para no depender de la disponibilidad de internet.

## Limitaciones conocidas

- El fingerprint pasivo de SO es una heurística ligera (TTL/ventana/opciones de un único paquete
  SYN), no tiene la profundidad de una base de firmas completa tipo p0f ni de un escaneo activo
  (`nmap -O`): identifica **familia** de sistema operativo con un nivel de confianza, no la versión
  exacta.
- La identidad de un dispositivo se basa principalmente en su IP; la MAC capturada solo es fiable
  para hosts en el mismo segmento L2 que el punto de captura (para tráfico enrutado, la MAC
  observada corresponde al último salto/router, no al host origen).
- La consulta a NVD depende de que el banner del servicio revele explícitamente producto y
  versión; sin ese dato, la vulnerabilidad "por versión" no se puede determinar de forma pasiva.
- El nombre de equipo solo se auto-detecta si el dispositivo emite alguno de los tráficos que se
  escuchan pasivamente (DHCP opción hostname, DNS/mDNS, NBNS/SMB/NetBIOS Session Service, o
  CDP/LLDP para switches/routers) con su propio nombre durante la captura; si no, queda en blanco
  hasta que se edite manualmente. Un equipo que solo hace SMB directo por TCP/445 (sin el
  envoltorio NetBIOS de TCP/139 ni ningún broadcast propio) tampoco tiene hoy una fuente pasiva de
  nombre disponible.
  La base de fabricantes por MAC solo cubre asignaciones OUI de bloque /24 (24 bits); los bloques
  más pequeños (MA-M/MA-S) no se resuelven y devuelven fabricante en blanco.
- Un dispositivo que solo aparece como destino de un intento de conexión sin respuesta (p. ej. un
  SYN a un puerto cerrado/filtrado) se inventaría igual que uno con tráfico bidireccional
  confirmado -- hoy no hay una distinción de "confianza" entre ambos casos (ver hoja de ruta).
- La captura en vivo procesa en un solo hilo consumidor (ver "Cómo procesa la captura en vivo"
  arriba); en un segmento con volumen sostenido muy por encima de lo que ese hilo puede ingerir,
  `dropped_count` empieza a crecer. La base de eso es el propio parsing en Python/Scapy, así que
  paralelizar a varios procesos consumidores (particionados por IP) es la vía de escala, no un
  cambio de librería de captura.
- El clasificador de **tipo de dispositivo** es pasivo por reglas, no una certeza: distingue muy
  bien PLC/RTU (protocolo OT) y equipos de red (CDP/LLDP), pero un servidor Windows y un PC
  Windows tienen el mismo fingerprint TCP/IP -- ahí depende de señales indirectas (nombre,
  cantidad de protocolos servidos) y puede devolver confianza baja o quedar sin clasificar.
  Resolverlo con certeza requiere una consulta activa (SNMP `sysDescr`, WMI), que es una pieza
  posterior y separada del motor pasivo (ver hoja de ruta, Bloque 1).
