# Resumen de datos

Periodo observado: 26/09/2026 – 03/10/2026 (UTC). Cifras de los logs en bruto, salvo las marcadas como Kibana y las del dashboard de T-Pot.

## Volumen por honeypot

| Honeypot                                                 | Eventos                 | IPs únicas      | Servicios principales                       |
| -------------------------------------------------------- | ----------------------- | --------------- | ------------------------------------------- |
| Dionaea                                                  | 64.801                  | 158             | SMB (47.852 conexiones), <br>MSSQL (16.781) |
| Honeytrap                                                | ~10.000 (Kibana)        | —               | Cualquier puerto sin otro honeypot asignado |
| Cowrie                                                   | 7.129                   | 352             | Telnet (1.534 sesiones), SSH (109)          |
| Adbhoney                                                 | 208                     | 32              | ADB (TCP/5555)                              |
| Otros (Redis, RDP, ConPot, Tanner, Mailoney, H0neytr4p…) | < 210 cada uno (Kibana) | Alrededor de 50 | Varios                                      |
| **Total de los honeypots (Kibana)**                      | **~83.000**             |                 |                                             |

_El total sale del dashboard de T-Pot (*Honeypot Attacks*) y solo cuenta eventos de los honeypots: los de Suricata, P0f y otros sensores van aparte (ver [lección 9](08-lecciones.md)). Honeytrap no se analiza en detalle: recoge las conexiones a cualquier puerto abierto que no atiende otro honeypot._

## Origen de los ataques

Datos del dashboard de T-Pot para todo el periodo (25/09 20:00 – 03/10 12:30 UTC). Cuentan **eventos de los honeypots**, no IPs únicas, así que una sola IP muy ruidosa puede mover a todo un país.

**Países con más eventos**, de mayor a menor: Tailandia, China, Estados Unidos, Rusia, India, Pakistán, Reino Unido, Vietnam, Taiwán y Colombia.

| ASN | Organización | Eventos |
| --- | --- | --- |
| 138524 | Triple T Broadband | 11.048 |
| 396982 | Google LLC | 7.751 |
| 154177 | Light Node | 4.821 |
| 9541 | Cyber Internet Services | 3.242 |
| 3462 | Data Communication Business Group | 3.174 |
| 45899 | VNPT Corp | 3.171 |
| 8452 | IDDQD-AS | 3.161 |
| 209206 | Voronezh Telecom | 3.156 |
| 4812 | China Telecom | 3.154 |
| 37061 | Safaricom | 3.152 |

**Lectura:**

- **Tailandia encabeza la lista por una sola IP.** Los 11.048 eventos del ASN 138524 son los de la IP más ruidosa de la semana, la herramienta de EternalBlue con huella de impacket que no entregó nada (ver [caso 2](04-caso-dionaea.md)). Es otro ejemplo de que el volumen no indica peligrosidad.
- **Varios ASN rondan los 3.150 eventos**, el mismo volumen que las siete IPs de esa herramienta de EternalBlue: el ranking lo marcan unas pocas IPs automatizadas, no muchas IPs distintas.
- **El ASN 9541 (Cyber Internet Services, Pakistán)** es la red de IP-COW-01, el bot del caso 3 (ver [OSINT](07-osint.md)).
- **Google LLC** aporta 7.751 eventos desde su nube, un origen habitual de escáneres alojados en servicios cloud.
- **P0f** identifica como sistema de origen más frecuente **Windows 7 u 8**, seguido de Linux 2.2.x-3.x: encaja con el peso del tráfico SMB hacia Dionaea.

## Servicios y credenciales

### Cowrie (SSH y Telnet)

- **1.643 sesiones**, el 93 % por Telnet: el tráfico es sobre todo de bots de IoT.
- **1.086 logins fallidos** desde 63 IPs y **83 correctos** desde 56 IPs.
- **Un único HASSH** en todo el SSH: una sola herramienta cliente.

| Usuarios más probados |     | Contraseñas más probadas |     |
| --------------------- | --- | ------------------------ | --- |
| `root`                | 473 | `1234`                   | 48  |
| `admin`               | 292 | _(vacía)_                | 35  |
| `super`               | 33  | `admin`                  | 31  |
| `user`                | 23  | `password`               | 24  |
| `administrator`       | 18  | `7ujMko0admin`           | 22  |
| `guest`               | 18  | `888888`                 | 22  |
| `support`             | 17  | `123456`                 | 20  |
| `supervisor`          | 17  | `12345`                  | 20  |

### Dionaea

#### SMB

- 47.852 conexiones al 445. Dos tipos de actividad muy distintos:
  - **Herramienta de EternalBlue con huella de impacket:** 8 IPs concentran ~33.000 conexiones (una de 11.048 y siete de ~3.150 cada una). Ninguna entrega de carga.
  - **Entregas de malware:** 21 capturas en la semana, todas por SMB. Siete de ~5,6 MB (WannaCry confirmado en una) y el resto de 80-95 KB.

#### MSSQL

- **14.240 intentos de login** desde 36 IPs únicas.
- Usuarios: `sa` (11.810) y `admin` (2.414). Prácticamente nada más.
- Contraseñas más probadas: `!QAZ2wsx` (28), vacía (22), `123456` (20), `111111` (19), `qwerty` (14), `1qaz2wsx` (12), `1qaz@WSX` (12). Destacan los **patrones de teclado**, que cumplen las políticas de complejidad.


## Malware capturado

| SHA-256                                                            | Tipo        | Detección VirusTotal | Familia                                            | Honeypot | Veces |
| ------------------------------------------------------------------ | ----------- | -------------------- | -------------------------------------------------- | -------- | ----- |
| `c05e2dab77349cd639aa837e7e121710b8a0718d8fc93fb4cc6458ae90e5c597` | DLL Windows | 67/71                | WannaCry (ransomware y gusano, CVE-2017-0144/0147) | Dionaea  | 1     |
| `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` | APK         | 49/68                | App maliciosa para Android (`com.ufo.miner`)       | Adbhoney | 8     |
| `71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5` | ELF ARM     | 39/64                | Gusano de minería que se propaga por ADB           | Adbhoney | 2     |

## Suricata

- **69.000 reglas cargadas**, sin errores.
- **4.113 alertas** de 51 firmas distintas en la semana.

| Firma                                                | Alertas | Qué la dispara                                                                                                                                                                              |
| ---------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SURICATA STREAM Packet with broken ack               | 1.628   | Un paquete TCP con el flag ACK activado pero con el número de confirmación a cero o incoherente. Típico de escáneres masivos que fabrican sus propios paquetes                              |
| SURICATA STREAM spurious retransmission              | 645     | Se retransmite un segmento cuyos datos el otro extremo ya había confirmado. Suele deberse a pérdida de paquetes, latencia o pilas TCP poco cuidadas de los bots                             |
| SURICATA SSH invalid banner                          | 308     | La primera línea de una conexión SSH no tiene el formato `SSH-2.0-…`. Aparece cuando un escáner habla otro protocolo contra un puerto SSH o envía basura para identificar el servicio       |
| ET INFO SSH session in progress on Unusual Port      | 306     | Tráfico SSH en un puerto que no es el 22. En T-Pot salta con el acceso de administración (64295) y con honeypots que exponen SSH en otros puertos                                           |
| SURICATA STREAM Packet with invalid timestamp        | 204     | La marca de tiempo TCP de un paquete no encaja con las anteriores de la misma conexión. Habitual en paquetes generados por herramientas de escaneo o en conexiones reutilizadas             |
| SURICATA STREAM reassembly sequence GAP              | 160     | Suricata no puede reensamblar el flujo porque faltan segmentos. Indica paquetes perdidos o que el sensor no vio parte de la conexión                                                        |
| SURICATA Applayer Detect protocol only one direction | 147     | Suricata identifica el protocolo de aplicación en un solo sentido de la conexión: el cliente envía datos y el servidor no responde (o al revés). Típico de sondeos que no esperan respuesta |
| SURICATA STREAM FIN recv but no session              | 121     | Llega un paquete de cierre (FIN) de una conexión que Suricata no tenía registrada. Lo provocan escaneos FIN y sesiones que el sensor ya había olvidado                                      |
| ET INFO Potentially unsafe SMBv1 protocol in use     | 53      | Un cliente negocia SMB versión 1, el protocolo vulnerable a EternalBlue (MS17-010). Es informativa: indica uso de SMBv1, no un ataque. Fue la única alerta en la entrega de WannaCry        |

---

[← Volver al README](../README.md)
