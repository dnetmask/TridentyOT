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
   - Se listan **todos** los activos vistos, incluida una IP de rango público: algunas redes
     LAN (mal) asignan rangos públicos a equipos internos, así que el rango de IP por sí solo ya
     no basta para decidir si algo es "de esta red". En su lugar, cada dispositivo trae un campo
     **`is_external`** (columna/etiqueta **Externo** en el frontend) que combina dos señales: si su
     IP parece pública **y** si alguna vez se le capturó transmitiendo, es decir, si tiene una MAC
     propia. La MAC solo se aprende del *emisor* de un paquete, nunca del destino (ver
     `inventory_service.get_or_create_device`), así que un host realmente externo -- alcanzado solo
     a través de un router -- nunca tiene MAC propia capturada, mientras que un equipo LAN mal
     configurado con IP pública sí la tiene (se le vio transmitir en el segmento capturado). Solo se
     marca **Externo** cuando ambas señales coinciden. `GET /api/inventory/devices` acepta
     `?hide_external=true` para ocultar esos equipos del listado si se prefiere; por defecto se
     muestran todos.
   - Todo es **editable manualmente** en cualquier momento (se detecte o no), sin perder el
     valor auto-detectado como referencia.
   - **Tipo de dispositivo** (columna **Tipo**): clasifica cada activo como **PLC**, **HMI**,
     **Servidor/VM**, **PC** o **Equipo de red** combinando, con reglas explicables (no ML), la
     evidencia que el resto del motor pasivo ya recolectó -- protocolo servido, anuncio CDP/LLDP
     (equipo de red con certeza), categoría del fabricante por OUI (industrial/redes/IT
     genérico/virtualización), palabras clave del nombre del equipo ("-HMI01", "-SRV", "-PC"...) y
     cantidad de protocolos distintos servidos. Un protocolo OT como servidor es **PLC** casi con
     certeza -- salvo que el propio fingerprint TCP/IP del paquete sea un Windows/Linux real, en
     cuyo caso es **HMI** (SCADA/estación de ingeniería: un PLC embebido nunca fingerprintea como
     un SO de propósito general). Un nombre que contenga "HMI" también clasifica como HMI
     directamente. Un fabricante **VMware** (interfaz de red virtual) clasifica directamente como
     **Servidor/VM**, a diferencia de un fabricante IT genérico (Dell, Lenovo...) que solo aporta
     una pista ambigua entre servidor y PC. Cada clasificación muestra su **evidencia** y una
     confianza 0-100%; los indicadores superiores de Inventario tienen un contador propio por cada
     tipo (**PLC**, **HMI**, **Servidores/VM**, **PCs**, **Equipos de red**) más "Otros equipos"
     para lo no clasificado, y se recalculan al vuelo si se activa "Ocultar equipos externos".
     Igual que nombre y fabricante, es **editable manualmente** sin perder el valor auto-detectado.
     Ver "Limitaciones conocidas" para el caso que esto no puede resolver de forma pasiva (servidor
     vs. PC Windows).
   - **Subtipo de equipo de red** (columna **Subtipo**, solo aplica a filas **Equipo de red**):
     una segunda clasificación independiente entre **Switch L2**, **Switch L3**, **Firewall**,
     **Access Point** o **Router/NAT**. Hoy solo **Router/NAT** se detecta solo (ver el punto
     siguiente); el resto es editable manualmente desde el detalle del dispositivo por ahora, a la
     espera de una señal pasiva confiable para auto-detectarlos.
   - **Detección de gateway/NAT**: un router que reenvía tráfico de internet transmite él mismo esa
     trama en el segmento LAN -- por la misma regla de "la MAC solo se aprende del emisor" (ver
     `inventory_service.get_or_create_device`), su MAC termina asociada a *cada IP pública distinta*
     que alguna vez reenvió, cada una como su propia fila de inventario. Cuando dos o más IPs
     públicas comparten una misma MAC, TridentyOT reconoce el patrón: elige la más antigua de esas
     filas públicas para representar el gateway y la marca como **Equipo de red / Router-NAT** con
     confianza 100%. Deliberadamente **nunca** elige una fila con IP privada para representarlo,
     aunque comparta la misma MAC: el mismo patrón (misma MAC como emisor) lo produce también un
     equipo real y distinto en otra subred cuyo tráfico de vuelta simplemente fue enrutado por ese
     mismo gateway (enrutamiento entre VLANs) -- no hay forma confiable de distinguir ambos casos, y
     adivinar mal etiquetaría un activo real como si fuera el gateway. Toda IP privada se deja
     siempre como equipo aparte, clasificado de forma independiente.

     Solo con `?hide_external=true` se colapsan las demás filas públicas duplicadas de esa MAC en
     la elegida como representante -- mismo criterio que el resto de IPs públicas (ver más arriba):
     visibles por defecto, ocultables solo bajo pedido. Una fila con IP privada que comparta esa
     misma MAC **nunca** se oculta, sin importar el valor de `hide_external` -- es un activo real y
     distinto, nunca un duplicado del gateway. Ninguna fila se borra: todas siguen apareciendo
     normalmente en **Flujos** y **Vulnerabilidades** pase lo que pase con su visibilidad en
     Inventario.
2. **Fingerprint pasivo de sistema operativo**: heurística basada en TTL inicial, tamaño de
   ventana TCP y opciones TCP del handshake (similar a p0f), sin enviar ningún tráfico activo.
3. **Detección de protocolos/servicios**: por puerto conocido y por firma de los primeros bytes
   del payload (HTTP, TLS, SSH, FTP...), cubriendo tanto protocolos IT comunes como protocolos
   OT/ICS (Modbus, DNP3, S7comm, EtherNet/IP, BACnet, IEC-104, OPC UA, etc.). **PROFINET** es un
   caso aparte: su tráfico de tiempo real corre crudo sobre Ethernet (EtherType `0x8892`, sin capa
   IP en absoluto), así que un PLC y sus IO-devices se identifican **solo por MAC**, igual que un
   switch que solo se ve por CDP/LLDP. Se reconocen sus variantes con el mismo nombre que usa
   Wireshark en la columna Protocol -- **PNIO_PS** (intercambio cíclico de datos de E/S en tiempo
   real, la inmensa mayoría del tráfico en una línea en marcha), **PN-DCP** (descubrimiento/
   configuración, que además trae el nombre configurado del equipo -- Name of Station -- igual que
   CDP/LLDP) y **PN-Alarm**. Un equipo visto hablando PROFINET, sin ninguna huella TCP/IP que lo
   contradiga (no tiene pila TCP/IP propia), se clasifica como **PLC**.
4. **Flujos / conversaciones**: qué par de dispositivos conversó, por qué protocolo/puerto y
   cuántos paquetes, agregado desde las sesiones TCP/UDP observadas (pestaña **Flujos**). Si
   cualquiera de los dos extremos es un dispositivo marcado **Externo** (ver punto 1), el flujo
   muestra esa misma etiqueta y puede ocultarse con "Ocultar flujos externos", que recalcula al
   vuelo los indicadores de la pestaña (total de flujos y flujos OT).
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
6. **Usuarios y control de acceso**: login con usuario/contraseña, tres perfiles —**Super Admin**
   (plataforma, sin organización propia, ve todas las organizaciones), **admin** (control total
   dentro de su propia organización) y **visualizador** (solo lectura)—. Ninguna API puede crear un
   Super Admin (ni `POST /api/users` ni `POST /api/organizations` lo permiten, a propósito, para no
   abrir un hueco de privilegio) — se arranca por variables de entorno, ver "Consola central /
   MSP" más abajo. Al primer arranque **sin** esas variables configuradas se crea en cambio el
   usuario `admin`/`admin` (perfil admin, instalación de un solo cliente autoalojado); cámbialo
   cuanto antes desde la pestaña **Usuarios**. El nombre de usuario es único por organización para
   admin/visualizador, y único de forma global solo entre los Super Admin (que no tienen
   organización de la cual distinguirse).
7. **Multi-organización e idioma**: el esquema de base de datos está preparado desde ya para dos
   topologías de despliegue -- un cliente grande que **auto-aloja** su propia instancia (una sola
   `Organization`, creada automáticamente en el primer arranque) o una futura **consola central**
   con varias organizaciones compartiendo una misma instancia/base de datos. Todo dato de captura
   (dispositivos, sesiones, hallazgos) queda asociado a su organización y las consultas de la API
   nunca cruzan esa frontera para admin/visualizador -- un Super Admin, en cambio, ve todas las
   organizaciones a la vez (ver `tests/test_multi_tenancy.py`). Un Super Admin da de alta nuevas
   organizaciones (con su primer usuario admin incluido) desde la pestaña **Organizaciones**; cada
   organización, a su vez, organiza sus sensores en `Site` (sede) → `Zone` (área de despliegue,
   con nivel de seguridad IEC&nbsp;62443 opcional) → `Sensor`, dados de alta por su propio admin
   desde la pestaña **Infraestructura** (visible en modo lectura para cualquier rol, ya que la
   plataforma también sirve para inventario/topología pura de TI). Toda instalación existente antes
   de este esquema recibió automáticamente un Sitio/Zona/Sensor "Default" al migrar (ver
   `tests/test_hierarchy.py`). Cada usuario tiene además un idioma preferido (**español** o
   **inglés**, ver más abajo) que se aplica tanto a la interfaz como al texto que generan los
   motores de fingerprint/vulnerabilidades.

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
- Para **descubrimiento activo con Nmap**: el binario `nmap` instalado, y esos mismos privilegios
  de raw socket -- pero sobre el binario `nmap` en sí, no sobre Python: `app/capture/
  nmap_discovery.py` lo invoca como proceso hijo separado (`subprocess.Popen(["nmap", ...])`), así
  que darle `setcap`/root solo al intérprete de Python (como en "Captura en vivo sin Docker" más
  abajo) no le da ningún privilegio a ese proceso hijo. Sin privilegios reales, nmap sigue
  funcionando pero degradado y sin avisar en el dashboard: sin descubrimiento por ARP (nunca hay
  MAC), sin `-O` (nunca hay sistema operativo), y el escaneo de puertos cae de SYN a conexión TCP
  completa.

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

Esto levanta dos servicios: `db` (Postgres 16, la base de datos primaria de la app) y `tridentyot`
(la imagen construida desde `backend/Dockerfile`: Python 3.11 + FastAPI + Scapy + libpcap/tcpdump),
publicando el dashboard/API en `http://localhost:8000`. Los datos de Postgres y los archivos
`.pcap` subidos quedan en los volúmenes con nombre `tridentyot_pgdata`/`tridentyot_data`, por lo que
sobreviven a `docker compose down` y a reinicios del contenedor (verificado: los dispositivos y
hallazgos siguen ahí después de un `docker restart`).

Un sensor de un solo cliente que prefiera no operar un servidor Postgres propio puede seguir
usando SQLite en su lugar -- ver `TRIDENTYOT_DATABASE_URL` en la tabla de variables de entorno más
abajo; en ese caso el servicio `db` puede quitarse del compose.

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

La subida devuelve de inmediato (el archivo se procesa en segundo plano); la tabla **Sesiones de
captura** muestra una barra de **Avance** con el porcentaje mientras la sesión está `running`,
calculado sobre los bytes del archivo ya leídos (`bytes_processed`/`total_bytes`, expuestos también
por `GET /api/capture/sessions`) -- ninguno de los dos formatos guarda en su cabecera un conteo
total de paquetes del que derivar un porcentaje más exacto. Para no competir por el único lock de
escritura de SQLite con el resto de la API mientras un archivo grande se procesa, estas
actualizaciones de avance se confirman como mucho una vez por segundo (no por paquete), y tras cada
una se cede la escritura brevemente antes de seguir -- lo justo para que otra petición concurrente
(un login, un PATCH de otra pestaña) tenga una oportunidad real de tomar el lock en vez de que este
hilo, más rápido, se lo vuelva a quedar primero.

### Descubrimiento activo (PROFINET DCP)

A diferencia de todo lo anterior en esta sección (100% pasivo), la pestaña **Descubrimiento
activo** de cada Zona -- justo debajo de Captura -- sí transmite tráfico. La opción **PROFINET
DCP** manda un único broadcast de capa 2 ("Identify All", el mismo mecanismo que usan Siemens
PRONETA y TIA Portal en "accessible devices": MAC multicast `01:0e:cf:00:00:00`, sin capa IP) y
escucha las respuestas durante una ventana corta y acotada (1-30 segundos) -- encuentra equipos
PROFINET aunque todavía no tengan una IP configurada. Cada dispositivo que responde entra al
inventario exactamente igual que uno observado pasivamente (reutiliza el mismo pipeline de
`process_packet`/`ingest_packet_record`), asociado a una sesión de captura propia
(`source_type=active_pnio_dcp`) para mantener el mismo scoping por Zona/Sitio. Requiere rol admin
y un sensor **en vivo** (uno externo no tiene una interfaz real sobre la que transmitir). Por API:

```bash
curl -X POST http://localhost:8000/api/discovery/profinet-dcp \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"interface": "eth0", "sensor_id": 1, "duration_seconds": 5}'
```

La opción **Nmap** hace un escaneo liviano de verdad (invoca el binario `nmap`, sin envoltorio
Python de por medio -- no aporta nada llamarlo directo y parsear su XML): puertos comunes (`-F`,
~100), detección de servicio/versión barata (`-sV --version-light`) y una pasada de sistema
operativo (`-O`). Deliberadamente **sin** scripts NSE ni escaneo agresivo -- hay casos documentados
de scripts NSE de ICS dejando un PLC real en estado de falla, así que quedan fuera por diseño, no
por límite técnico. Cada host que responde entra al inventario igual que uno pasivo (mismo
`get_or_create_device`/`upsert_protocol`/`apply_os_guess`), y el banner producto/versión que nmap
identifica alimenta la misma búsqueda en NVD que ya usa la captura pasiva
(`vuln.rules.extract_banner_product_version`) -- ese es el objetivo real de esta opción: no solo
inventariar, sino darle a Vulnerabilidades algo que buscar cuando la captura pasiva todavía no vio
suficiente tráfico del servicio como para tener su banner. El nombre por DNS reverso que nmap
resuelve por su cuenta (`<hostnames>` en su XML) y el banner de un servicio HTTP(S) detectado
también se procesan igual que sus equivalentes pasivos (`apply_hostname_hints`/
`apply_identity_hints`), no solo el puerto/versión/SO. Requiere rol admin y un sensor **en vivo**.

El escaneo sale por la interfaz física configurada en ese sensor (`Sensor.interface`, editable
desde **Infraestructura** o `PATCH /api/sensors/{id}`) vía `nmap -e <interfaz>` -- importante en un
host con más de una NIC, porque nmap solo puede resolver la **MAC** de un equipo por ARP cuando el
objetivo es alcanzable en capa 2 desde la interfaz por la que sale el escaneo. Sin eso (o corriendo
en la red *bridge* por defecto de Docker, que solo ve la NIC virtual del contenedor -- ver
"Captura en vivo dentro de Docker" más arriba, la misma limitación aplica acá) los dispositivos
igual se inventarían por puertos/servicios/SO, pero sin MAC ni fabricante derivado de ella.

No tiene un tiempo máximo fijo -- corre hasta que nmap termina solo o hasta que se lo detiene a
mano (botón **Detener**, o `POST /api/discovery/nmap/stop/{id}`). Mientras corre, una barra de
avance muestra cuántas de las IPs del objetivo ya se escanearon (parseando en vivo la salida de
`nmap -v`) y el contador de "equipos identificados" sube en tiempo real, no solo al terminar --
cada host que nmap ya reportó se reingresa al inventario en cada actualización (`GET
/api/capture/sessions/{id}` expone `progress_percent`/`packet_count` para esto). Si se detiene a
mitad de camino, no se pierden los resultados ya obtenidos: el XML parcial de nmap queda sin sus
etiquetas de cierre, pero cada bloque `<host>` que sí se terminó de escribir se recupera igual (ver
`_make_xml_parseable` en `app/capture/nmap_discovery.py`), solo se descarta el host que estaba a
medio escanear en el momento de la interrupción. Por API:

```bash
curl -X POST http://localhost:8000/api/discovery/nmap \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "192.168.1.0/24", "sensor_id": 1}'

curl -X POST http://localhost:8000/api/discovery/nmap/stop/42 \
  -H "Authorization: Bearer $TOKEN"
```

La opción **SNMP** hace una consulta liviana de verdad: un GET a `sysDescr`/`sysObjectID`/`sysName`
(MIB-II) por cada IP del objetivo, usando la propia capa SNMP/ASN.1 de Scapy (`app/capture/
snmp_discovery.py`) -- no una librería SNMP aparte ni los binarios `snmpget`/`snmpwalk` de net-snmp.
Solo SNMPv1/v2c con community string (por defecto `public`, editable); SNMPv3 queda fuera de
alcance a propósito, igual que los scripts NSE de Nmap: el modelo de seguridad de SNMPv3 necesita
un handshake de sesión real que la capa SNMP de Scapy no implementa, y armar eso ahí dejaría de ser
un "escaneo liviano". La mayoría de las IPs de un barrido simplemente no van a responder -- SNMP
viene deshabilitado por defecto en la mayoría de los equipos -- así que un `/24` casi en silencio es
el resultado esperado, no una falla. Requiere rol admin y un sensor **en vivo**; igual que Nmap, sale
por la interfaz configurada en el sensor (`Sensor.interface`) cuando hay una.

Mismo esquema de **sin tiempo máximo + barra de avance + Detener** que Nmap (`POST
/api/discovery/snmp/stop/{id}`): como SNMP no tiene una señal de progreso propia como el stdout
verboso de nmap, el barrido avanza en tandas de IPs (`sr()` de Scapy manda toda la tanda junta y
espera una ventana de tiempo compartida) y el progreso es simplemente "cuántas IPs de la tanda ya se
mandaron y esperaron". Cada host que responde entra al inventario con la misma metodología completa
que el resto de las fuentes: `sysDescr` alimenta el fingerprint de SO (con confianza media, ya que es
texto libre autoreportado, no un enum), `sysName` pasa por `apply_hostname_hints` (mismo chequeo de
colisión que DNS/mDNS/NBNS), y `sysObjectID` -- un OID numérico asignado por IANA, no un nombre de
fabricante -- se guarda solo como evidencia para que un humano lo busque, nunca traducido a
Device.vendor/model (misma regla que ya aplica a los vendorId numéricos de CIP/BACnet). Por API:

```bash
curl -X POST http://localhost:8000/api/discovery/snmp \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "192.168.1.0/24", "sensor_id": 1, "community": "public", "version": "v2c"}'

curl -X POST http://localhost:8000/api/discovery/snmp/stop/42 \
  -H "Authorization: Bearer $TOKEN"
```

### Topología de red

La pestaña **Topología** dibuja un grafo de la red (`GET /api/topology`) con los mismos
dispositivos que ya aparecen en Inventario -- cada uno con un ícono según su `device_type`
(PLC/HMI/servidor/PC/router/switch), renderizado con [Cytoscape.js](https://js.cytoscape.org/)
(vendorizado localmente en `backend/app/static/vendor/`, sin CDN: un sensor OT suele correr en una
red aislada sin salida a internet).

Todo enlace dibujado es un `NetworkLink` (tabla `network_links`): una afirmación explícita de alguien
que conoce el cableado real -- **confirmado** (línea sólida azul) o **dudoso/sin confirmar** (línea
punteada naranja), ambos con los puertos de cada lado si se conocen. La Topología deliberadamente
**no** se calcula desde `Flow` (quién habló con quién): eso es un grafo *lógico* de comunicación
observada, nunca una prueba de que existe un cable físico entre esos dos equipos -- dos dispositivos
pueden hablar a través de varios switches intermedios sin estar conectados directamente, y mezclar
ambas cosas en el mismo dibujo termina mostrando enlaces que no existen. Mientras no haya una fuente
confiable de adyacencia física real, un dispositivo sin `NetworkLink` sale suelto, sin ninguna línea.

#### Enlaces reales desde un switch (tabla MAC, ARP, CDP/LLDP)

Además de un enlace 100% manual, un `NetworkLink` puede venir de datos que el propio switch reporta --
nunca de tráfico observado. `NetworkLink.source` guarda de dónde salió cada uno: `manual` (un humano lo
creó en el grafo), `mac_table` (una interfaz con exactamente una MAC en la tabla de direcciones del
switch), `cdp`/`lldp` (el switch anunció directamente su vecino y el puerto de cada lado -- la evidencia
más fuerte que existe, porque lo dice el propio equipo). Un enlace `manual` nunca se pisa por un walk o
import posterior para el mismo par de dispositivos; uno derivado (`mac_table`/`cdp`/`lldp`) sí se
actualiza si un hallazgo más nuevo trae datos distintos. Una interfaz con **más de una MAC** en su tabla
es la señal clásica de un uplink a otro switch -- se reporta como "uplink sospechoso" pero nunca se
dibuja un enlace ahí, porque la tabla MAC sola no dice a qué otro switch va (eso es lo que resuelve
CDP/LLDP). Un vecino CDP/LLDP que no coincide con ningún Device del inventario tampoco crea un Device
nuevo -- queda listado como "vecino sin identificar" para crear ese switch a mano y reimportar.

Esto se controla desde **Descubrimiento activo → Topología por switch**: elegí un switch ya visto en
Inventario o creá uno manual (`POST /api/inventory/devices` -- opcionalmente atribuido a un Sensor/Zona
vía `sensor_id`, igual que cualquier otro dispositivo de descubrimiento activo; sin eso, el switch no
tiene `capture_session_id` y por lo tanto no aparece en ninguna vista de Topología por Zona/Sitio, solo
en una consulta sin filtrar). Después:

- **Vía SNMP** (`POST /api/discovery/snmp/switch-walk`): camina (GETNEXT, no un GET puntual)
  BRIDGE-MIB (`dot1dTpFdbTable`/`dot1dBasePortIfIndex`/`ifDescr`, la tabla MAC-a-puerto), IP-MIB
  (`ipNetToMediaTable`, la tabla ARP del switch) y LLDP-MIB (`lldpRemTable`) en los switches indicados
  (una lista explícita de IPs, nunca un CIDR completo -- un walk son varios paquetes por equipo, no uno
  solo como el sweep de `POST /api/discovery/snmp`). Solo SNMPv1/v2c, misma limitación que el sweep
  liviano (scapy no implementa el handshake de sesión de SNMPv3 -- ver docstring de
  `snmp_discovery.py`). **CDP no se camina por SNMP** -- CDP-MIB codifica la dirección del vecino en un
  formato que necesita calibrarse contra un equipo real; un switch Cisco con CDP sigue entrando por la
  vía manual.
- **Import manual** (`POST /api/discovery/switch-tables/import`): pegás la salida de
  `show mac address-table` / `show arp` / `show cdp neighbors detail` (o el `show lldp neighbors
  detail` equivalente) directo de la CLI. Compatible con **Cisco** (parseo completo, basado en el
  formato real de IOS) y **Siemens Scalance** (mejor esfuerzo: no hay una muestra real de un equipo
  todavía para calibrar el formato exacto -- se ajusta en cuanto se prueba contra uno real, el texto
  crudo queda guardado en `SwitchTableImport.raw_text` justo para eso). Devuelve un resumen: filas
  leídas, enlaces creados/actualizados, uplinks sospechosos, vecinos sin identificar.

```bash
curl -X POST http://localhost:8000/api/inventory/devices \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"custom_name": "switch-linea-1", "ip": "10.0.1.2", "device_type_secondary": "switch_l2", "sensor_id": 3}'

curl -X POST http://localhost:8000/api/discovery/switch-tables/import \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"device_id": 12, "table_type": "mac_table", "vendor": "cisco", "raw_text": "Vlan Mac Address Type Ports\n1 0011.2233.4455 DYNAMIC Gi0/1\n"}'

curl -X POST http://localhost:8000/api/discovery/snmp/switch-walk \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"targets": ["10.0.1.2"], "sensor_id": 3, "community": "public", "version": "v2c"}'
```

**Uso desde el dashboard** (rol admin): activar "Modo edición", hacer click en un dispositivo y
luego en otro para crear un enlace nuevo (se abre un formulario con puerto de cada lado, estado y
notas); hacer click en un enlace existente para editarlo o borrarlo. Un visualizador ve el mismo grafo
pero sin esas acciones. Por API:

```bash
curl http://localhost:8000/api/topology \
  -H "Authorization: Bearer $TOKEN"

curl -X POST http://localhost:8000/api/topology/links \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"device_a_id": 10, "device_b_id": 42, "source_port": "Gi0/3", "target_port": "eth0", "status": "confirmed"}'

curl -X PATCH http://localhost:8000/api/topology/links/7 \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"source_port": "Gi0/3", "target_port": "eth0", "status": "uncertain", "notes": "revisar en sitio"}'

curl -X DELETE http://localhost:8000/api/topology/links/7 -H "Authorization: Bearer $TOKEN"
```

**Topología del Sitio (todas las Zonas unificadas):** además de la Topología por Zona (la que se ve
al entrar a una Zona puntual), el panel lateral tiene una entrada "Topología del Sitio" a nivel de
Sitio -- "Todas las Zonas unificadas" -- que llama al mismo endpoint con `?site_id=X` en vez de
`?zone_id=X`. Es la unión de los dispositivos y enlaces de todas las Zonas de ese Sitio, calculada
por el mismo `GET /api/topology` sin ningún paso extra de "unificación": un enlace humano entre
dispositivos de dos Zonas distintas, invisible en la vista de cualquiera de esas Zonas por separado
(sale del alcance de ambas), sí aparece aquí. Cuando la vista abarca más de una Zona, cada nodo trae
además `zone_id`/`zone_name` (a qué Zona pertenece el dispositivo que primero lo capturó) y el
frontend dibuja una caja compuesta de Cytoscape.js por Zona para agruparlos visualmente -- una vista
de una sola Zona no tiene nada que agrupar y se ve exactamente igual que antes.

```bash
curl "http://localhost:8000/api/topology?site_id=3" -H "Authorization: Bearer $TOKEN"
```

### Ejecutar el escaneo de vulnerabilidades

```bash
curl -X POST http://localhost:8000/api/vuln/scan \
  -H "Content-Type: application/json" \
  -d '{"use_nvd": true}'
```

`use_nvd: false` limita el escaneo a las reglas locales (sin salir a internet).

### Idioma (español/inglés)

El dashboard tiene un interruptor de idioma en la barra lateral (junto al de tema claro/oscuro)
que traduce la navegación, títulos de sección, encabezados de tabla y formularios entre **español**
y **inglés**. La elección se guarda en la cuenta del usuario (`PATCH /api/auth/me`, campo `locale`)
y se aplica también al texto que generan los motores de fingerprint y vulnerabilidades
(`device_type_evidence`, título/descripción/evidencia de cada hallazgo) -- ese texto se guarda una
sola vez en ambos idiomas y se traduce al vuelo según quién lo consulte, así que dos usuarios de la
misma organización pueden ver el mismo hallazgo cada uno en su propio idioma. Las descripciones de
CVE que vienen directamente de NVD no se traducen (son texto de un tercero, siempre en inglés).
Cobertura actual: la interfaz estática (menú, títulos, encabezados, formularios) y todo el texto de
evidencia/hallazgos generado por el backend están cubiertos; algunas etiquetas generadas
dinámicamente en las tablas (por ejemplo botones "Detener"/"Borrar" o el mensaje de tabla vacía)
todavía se muestran en español pase lo que pase -- ver `app/i18n` en el backend y el diccionario
`I18N` en `static/index.html`.

### Tema claro/oscuro

El dashboard sigue por defecto la preferencia del sistema operativo (`prefers-color-scheme`), y
tiene un interruptor manual en la barra lateral (debajo de la navegación) para forzar uno u otro;
la elección manual queda guardada en el navegador (`localStorage`) y tiene prioridad sobre la
preferencia del sistema en las siguientes visitas. Es un cambio puramente de variables CSS -- los
colores semánticos (OT, PLC, HMI, severidades de Vulnerabilidades) se mantienen reconocibles en
ambos temas, solo se reajusta el contraste de algunos (naranja/ámbar más oscuros sobre fondo
blanco).

### Borrar toda la base de datos (empezar una captura en blanco)

El dashboard se refresca solo, cada 15 segundos, en todas sus pestañas -- no hace falta ningún
botón "Actualizar". Las pestañas **Inventario** y **Flujos** muestran un pequeño temporizador
("Se actualiza en Xs") junto a sus filtros que cuenta hacia atrás hasta el próximo refresco.
Cuando lo que hace falta es partir de cero (no solo ver datos nuevos), la
pestaña **Captura** tiene una sección "Zona de peligro" con un botón que borra **todas** las
sesiones de captura, dispositivos, protocolos, flujos y hallazgos de vulnerabilidades -- las
cuentas de usuario nunca se tocan. Pide confirmación antes de ejecutar, porque no se puede
deshacer. Por API (requiere rol admin o Super Admin):

```bash
curl -X DELETE http://localhost:8000/api/capture/wipe \
  -H "Authorization: Bearer $TOKEN"
```

### Reporte automático de vulnerabilidades y exportación a PDF

Además del refresco general de 15 segundos, la pestaña **Vulnerabilidades** ejecuta por su cuenta
un escaneo basado en reglas (equivalente a `?use_nvd=false`, para no depender de salir a internet
cada minuto) cada **60 segundos**, con su propio temporizador ("Próximo reporte automático en
Xs"). El botón **Exportar PDF** genera, con los hallazgos actualmente cargados, una vista de
reporte de una sola página con el logo de TridentyOT, fecha de generación, resumen por severidad
y la tabla completa de hallazgos, y abre el diálogo de impresión del navegador (**Guardar como
PDF**) ya con esa vista lista -- sin depender de ningún servicio externo de generación de PDF.

## Configuración (variables de entorno)

| Variable | Descripción | Default |
|---|---|---|
| `TRIDENTYOT_DATA_DIR` | Directorio de archivos pcap subidos (y de la DB si se usa SQLite) | `backend/data` |
| `TRIDENTYOT_DATABASE_URL` | URL de SQLAlchemy completa; si se define, ignora las variables `TRIDENTYOT_POSTGRES_*` de abajo. Acepta `sqlite:///...` para un despliegue sin Postgres | Postgres armado con las variables `TRIDENTYOT_POSTGRES_*` |
| `TRIDENTYOT_POSTGRES_HOST` / `_PORT` / `_DB` / `_USER` / `_PASSWORD` | Credenciales de Postgres usadas para construir `TRIDENTYOT_DATABASE_URL` por defecto | `db` / `5432` / `tridentyot` / `tridentyot` / `tridentyot` |
| `NVD_API_KEY` | API key de NVD (opcional, sube el límite de tasa a 50 req/30s) | — |
| `NVD_CACHE_TTL_SECONDS` | Tiempo de vida del caché de resultados de NVD | 86400 (24h) |
| `TRIDENTYOT_DEFAULT_FILTER` | Filtro BPF por defecto para captura en vivo | `ip or arp` |
| `TRIDENTYOT_SESSION_LIFETIME_SECONDS` | Duración del token de sesión antes de expirar | 604800 (7 días) |
| `TRIDENTYOT_DEFAULT_ADMIN_USERNAME` | Usuario admin creado en el primer arranque (si no hay usuarios **y no configuraste un Super Admin, ver abajo**) | `admin` |
| `TRIDENTYOT_DEFAULT_ADMIN_PASSWORD` | Contraseña de ese admin inicial — **cámbiala tras el primer login** | `admin` |
| `TRIDENTYOT_SUPER_ADMIN_USERNAME` | Si se define, arranca en modo consola central: crea un Super Admin en el primer arranque (sin organización, sin `Organization` "Default" de por medio) en vez del admin/organización por defecto de arriba | — (deshabilitado) |
| `TRIDENTYOT_SUPER_ADMIN_PASSWORD` | Contraseña de ese Super Admin — **obligatoria** si definiste `TRIDENTYOT_SUPER_ADMIN_USERNAME` (el arranque falla con un error claro si falta) | — |

### Consola central / MSP: arrancar con un Super Admin

Un despliegue de un solo cliente (auto-alojado) no necesita nada de esto -- deja las dos
variables `TRIDENTYOT_SUPER_ADMIN_*` sin definir y el primer arranque crea el usuario
`admin`/`admin` de siempre. Pero si estás levantando la consola central de Netmask (o cualquier
instancia pensada para servir a varios clientes desde el día uno, patrón MSP), no hay ningún
endpoint que pueda crear un Super Admin -- ni `POST /api/users` ni `POST /api/organizations` lo
permiten, a propósito, para que ninguna cuenta de una organización pueda auto-otorgarse ese rol.
Definí las dos variables antes del primer arranque:

```bash
TRIDENTYOT_SUPER_ADMIN_USERNAME=root TRIDENTYOT_SUPER_ADMIN_PASSWORD=cambiame-ya \
  docker compose up -d
```

Con eso, el primer login (`root`/`cambiame-ya`) entra directo a la pestaña **Organizaciones** —
la instancia arranca sin ninguna organización todavía, ni una "Default" de relleno — y desde ahí
se da de alta la primera organización real (con su propio usuario admin incluido en el mismo
formulario). Cada organización, después, entra a **Infraestructura** para dar de alta sus propios
`Site` (sedes) → `Zone` (áreas, con nivel de seguridad IEC&nbsp;62443 opcional) → `Sensor`.
Cambiá la contraseña del Super Admin cuanto antes desde la pestaña **Usuarios**... salvo que
prefieras dejarla fija por variable de entorno y rotarla ahí mismo en el próximo despliegue.

## Actualizar una instalación existente

Al iniciar, la app agrega automáticamente a la base de datos cualquier columna nueva que una
versión más reciente del código haya introducido (por ejemplo, `custom_name`/`vendor` en
dispositivos), sin borrar ni tocar los datos ya existentes. Basta con actualizar el código
(`git pull` / reconstruir la imagen Docker) y reiniciar — no hace falta borrar la base de datos.
Esto cubre columnas nuevas, que es como ha evolucionado el esquema hasta ahora; un cambio más
profundo (renombrar o eliminar una columna) sí requeriría una migración manual.

Una instalación previa a la organización/multi-tenant (sin columna `organization_id`) se migra
igual de forma automática y sin intervención: al iniciar, la app crea una `Organization` por
defecto y le asigna todos los usuarios/dispositivos/sesiones existentes -- una instalación
de un solo cliente sigue funcionando exactamente igual después de actualizar, sin ningún dato
visible ni comportamiento distinto (verificado en `tests/test_db_migration.py` contra una base
con el esquema anterior). Migrar de SQLite a Postgres, en cambio, sí es manual: no hay una
herramienta de copia de datos entre motores incluida todavía -- para un despliegue nuevo, definir
`TRIDENTYOT_DATABASE_URL` (o las variables `TRIDENTYOT_POSTGRES_*`) apuntando a Postgres desde el
primer arranque evita tener que migrar después.

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
  observada corresponde al último salto/router, no al host origen). Si esa IP termina repetida en
  dos registros (conflicto real de IP en la red, o dos cargas/capturas corriendo a la vez que
  crean cada una un registro para la misma IP antes de verse entre sí -- la IP sola no tiene una
  restricción de unicidad en la base de datos), el motor de inventario no falla: converge de forma
  determinista en el registro más antiguo para esa IP en vez de lanzar un error a media captura.
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
- Un `Device`/`Flow`/`DeviceProtocol` solo guarda **un** `capture_session_id` -- el de la captura que
  más recientemente lo confirmó (ver `inventory_service.get_or_create_device`/`upsert_flow`/
  `upsert_protocol`), y de ahí sale a qué Zona/Sitio pertenece en cualquier vista filtrada
  (`_filter_by_zone_or_site`). Un dispositivo real, alcanzable simultáneamente desde el Sensor de dos
  Zonas distintas, solo aparece en la que lo capturó por última vez -- no en ambas a la vez. No hay
  hoy una tabla de auditoría muchos-a-muchos que recuerde cada Zona que alguna vez lo vio; la vista
  **Reportes** (sin filtro de Zona/Sitio) es la única que siempre lo muestra, sin importar cuál lo
  capturó más recientemente.
