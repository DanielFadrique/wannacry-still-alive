# Mapeo a MITRE ATT&CK

- **Periodo:** 26/09/2026 – 03/10/2026 (UTC)
- **Versión de ATT&CK:** v19 (Enterprise).
- **Matriz:** Enterprise en los tres honeypots. En Adbhoney se usa como aproximación, porque ADB funciona como una shell de Linux.

El detalle de cada técnica (comando, posición en la sesión, recuento, status, confianza y razonamiento) está en su caso de estudio:

- [Caso 1 – Adbhoney](03-caso-adbhoney.md) · fichas ADB-01 a ADB-08
- [Caso 2 – Dionaea](04-caso-dionaea.md) · fichas DIO-01 a DIO-05
- [Caso 3 – Cowrie](05-caso-cowrie.md) · fichas COW-01 a COW-05

## Estado

| Honeypot | Fichas          | Campaña o IP analizada                                                                                |
| -------- | --------------- | ----------------------------------------------------------------------------------------------------- |
| Adbhoney | ADB-01 a ADB-08 | IP-ADB-01: crypto miner app `com.ufo.miner` + `trinity`                                               |
| Dionaea  | DIO-01 a DIO-05 | IP-DIO-01: equipo infectado por WannaCry que explota MS17-010 (EternalBlue) y entrega la DLL (5,59 MB) |
| Cowrie   | COW-01 a COW-05 | IP-COW-01: bot de botnet IoT tipo Mirai por Telnet (marcador `SAEXRG`)                                |

**Resumen:** 18 fichas y 16 técnicas distintas de ATT&CK: **13 observadas** en los honeypots y **3 como capacidad** del malware capturado (T1496 minería, T1486 cifrado de WannaCry y T1210 propagación). Las tres campañas terminan igual: el atacante consigue entrar o explotar el servicio, pero el honeypot nunca ejecuta su carga.

---

## Convenciones

- **Status:** 
	- Observado (lo vio el honeypot) 
	- Capacidad (lo puede hacer el malware, pero no ocurrió) 
	- Hipótesis (deducción sin prueba directa)
- **Confianza:** 
	- Alta
	- Media
	- Baja
- **IDs:** prefijo por honeypot y número en **orden cronológico** de la sesión: `ADB-xx` (Adbhoney), `DIO-xx` (Dionaea), `COW-xx` (Cowrie). Si una técnica se repite más adelante en la sesión, el comando nuevo se añade a la ficha que ya existe. Si la confianza cambia entre comandos de una misma ficha, se indica por comando.
- **Privacidad:** las IPs de origen se sustituyen por alias (`IP-ADB-01`, `IP-DIO-01`, `IP-COW-01`…); la correspondencia real se guarda solo en local. Sin IP del VPS, sin nombre del sensor y con URLs desactivadas (`hxxp://`, `[.]`).
- **Recuentos:** se distingue el recuento de la IP analizada del total del periodo en todas las IPs.

---

## Índice global

| ID | Honeypot | Táctica | Técnica | Status | Confianza |
|---|---|---|---|---|---|
| ADB-01 | Adbhoney | Initial Access | T1133 External Remote Services | Observado | Media |
| ADB-02 | Adbhoney | Discovery | T1518 Software Discovery | Observado | Alta |
| ADB-03 | Adbhoney | Command and Control | T1105 Ingress Tool Transfer | Observado | Alta |
| ADB-04 | Adbhoney | Execution | T1059.004 Unix Shell | Observado | Media |
| ADB-05 | Adbhoney | Stealth | T1070.004 File Deletion | Observado | Alta (cmd. 3) · Baja (cmd. 6) |
| ADB-06 | Adbhoney | Discovery | T1057 Process Discovery | Observado | Alta |
| ADB-07 | Adbhoney | Defense Impairment | T1222.002 Linux and Mac File and Directory Permissions Modification | Observado | Media |
| ADB-08 | Adbhoney | Impact | T1496 Resource Hijacking | Capacidad | Alta |
| DIO-01 | Dionaea | Reconnaissance | T1595.002 Vulnerability Scanning | Observado | Media |
| DIO-02 | Dionaea | Initial Access | T1190 Exploit Public-Facing Application | Observado | Alta |
| DIO-03 | Dionaea | Command and Control | T1105 Ingress Tool Transfer | Observado | Alta |
| DIO-04 | Dionaea | Impact | T1486 Data Encrypted for Impact | Capacidad | Alta |
| DIO-05 | Dionaea | Lateral Movement | T1210 Exploitation of Remote Services | Capacidad | Media |
| COW-01 | Cowrie | Credential Access | T1110.001 Password Guessing | Observado | Alta |
| COW-02 | Cowrie | Initial Access | T1078.001 Default Accounts | Observado | Alta |
| COW-03 | Cowrie | Execution | T1059.004 Unix Shell | Observado | Alta |
| COW-04 | Cowrie | Discovery | T1083 File and Directory Discovery | Observado | Media |
| COW-05 | Cowrie | Stealth · Discovery | T1497.001 System Checks | Observado (comando) · Hipótesis (intención) | Baja |

## Vista conjunta por técnica

Base para las capas de ATT&CK Navigator: una capa "Observado" con las técnicas vistas en los honeypots y otra "Capacidad" con lo que el malware puede hacer pero no ocurrió.

| Técnica | Táctica | Adbhoney | Dionaea | Cowrie | Status global |
|---|---|---|---|---|---|
| T1133 External Remote Services | Initial Access | ADB-01 | | | Observado |
| T1518 Software Discovery | Discovery | ADB-02 | | | Observado |
| T1105 Ingress Tool Transfer | Command and Control | ADB-03 | DIO-03 | | Observado |
| T1059.004 Unix Shell | Execution | ADB-04 | | COW-03 | Observado |
| T1070.004 File Deletion | Stealth | ADB-05 | | | Observado |
| T1057 Process Discovery | Discovery | ADB-06 | | | Observado |
| T1222.002 Linux and Mac File and Directory Permissions Modification | Defense Impairment | ADB-07 | | | Observado |
| T1496 Resource Hijacking | Impact | ADB-08 | | | Capacidad |
| T1595.002 Vulnerability Scanning | Reconnaissance | | DIO-01 | | Observado |
| T1110.001 Password Guessing | Credential Access | | | COW-01 | Observado |
| T1078.001 Default Accounts | Initial Access | | | COW-02 | Observado |
| T1083 File and Directory Discovery | Discovery | | | COW-04 | Observado |
| T1497.001 System Checks | Stealth · Discovery | | | COW-05 | Observado (baja confianza) |
| T1210 Exploitation of Remote Services | Lateral Movement | | DIO-05 | | Capacidad |
| T1190 Exploit Public-Facing Application | Initial Access | | DIO-02 | | Observado |
| T1486 Data Encrypted for Impact | Impact | | DIO-04 | | Capacidad |

## Criterios de mapeo

- **Se mapea el comportamiento, no la herramienta.** Cada ficha explica qué hace el comando y por qué encaja con la técnica.
- **Observado frente a Capacidad.** Lo que el honeypot registró es Observado. Lo que la muestra puede hacer pero no ocurrió (porque los honeypots no ejecutan el malware) es Capacidad y va en una capa aparte del Navigator.
- **No mapear de más.** Lo que no encaja claramente queda fuera y se explica en "Lo que no se mapea" de cada caso (por ejemplo `nohup`, que no es persistencia, o `su -c`).
- **La confianza baja se dice.** Un mapeo dudoso con su razonamiento aporta más que uno forzado.


---

[← Volver al README](../README.md)
