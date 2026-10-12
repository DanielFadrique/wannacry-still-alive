# Honeypot T-Pot: de los ataques reales a MITRE ATT&CK

Durante una semana expuse un honeypot multiservicio ([T-Pot](https://github.com/telekom-security/tpotce)) a Internet y analicé lo que llegó como lo haría un SOC Analyst: reconstruir cada ataque desde los logs, correlacionar varias fuentes, mapearlo a MITRE ATT&CK y proponer cómo detectarlo.

## Cifras de la semana (26/09 – 03/10/2026)

|                                |                                                                      |
| ------------------------------ | -------------------------------------------------------------------- |
| Eventos registrados            | ~83.000                                                              |
| Honeypot más atacado           | Dionaea (SMB y MSSQL), 78 % del total                                |
| IPs únicas                     | 158 en Dionaea · 352 en Cowrie · 32 en Adbhoney                      |
| Muestras de malware capturadas | WannaCry (Windows), minero para Android y un binario de minería ELF ARM |
| Técnicas de ATT&CK mapeadas    | 16 (13 observadas + 3 como capacidad del malware)                    |

_Cifras detalladas en [resumen de datos](docs/02-resumen-datos.md)._

## Tres hallazgos

1. **WannaCry sigue propagándose casi diez años después.** Un Windows 7/8 infectado explotó MS17-010 contra el honeypot y entregó la DLL del ransomware en 5 conexiones. La IP no estaba en Elastic: se encontró en la base de datos interna de Dionaea y se confirmó con Suricata y P0f. → [Caso 2](docs/04-caso-dionaea.md)
2. **El volumen no indica peligrosidad.** Una herramienta de EternalBlue lanzó más de 11.000 conexiones desde una sola IP sin conseguir nada; WannaCry entregó su carga con 5.
3. **Suricata tenía ~69.000 reglas cargadas y no generó ni una firma de exploit** en toda la semana, ni siquiera con una explotación real de MS17-010. → [Lecciones](docs/08-lecciones.md)

Capas interactivas en ATT&CK Navigator: [Observado](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FDanielFadrique%2Fwannacry-still-alive%2Fmain%2Fnavigator%2Fobservado.json) · [Capacidad](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FDanielFadrique%2Fwannacry-still-alive%2Fmain%2Fnavigator%2Fcapacidad.json) · [ficheros JSON](navigator/)

## Casos de estudio

| Caso | Honeypot | Qué ocurrió | Técnicas |
|---|---|---|---|
| [1 – Minero por ADB](docs/03-caso-adbhoney.md) | Adbhoney | Gusano que instala dos mineros en un Android con ADB expuesto | 8 |
| [2 – WannaCry](docs/04-caso-dionaea.md) | Dionaea | Equipo infectado que explota MS17-010 y entrega el ransomware | 5 |
| [3 – Botnet IoT](docs/05-caso-cowrie.md) | Cowrie | Bot tipo Mirai que entra por Telnet con credenciales de fábrica | 5 |

## Contenido del repositorio

| Documento | Qué contiene |
|---|---|
| [Metodología](docs/01-metodologia.md) | Despliegue, fuentes de datos, anonimización y limitaciones |
| [Resumen de datos](docs/02-resumen-datos.md) | Cifras agregadas, credenciales, servicios y malware |
| [Mapeo MITRE ATT&CK](docs/06-mapeo-mitre.md) | Índice de técnicas, vista conjunta y criterios |
| [OSINT de IPs](docs/07-osint.md) | ¿Atacantes o dispositivos infectados? |
| [Lecciones aprendidas](docs/08-lecciones.md) | Qué funcionó, qué no y qué cambiaría |
| [IOCs](iocs/README.md) | Hashes del malware capturado, con enlace a VirusTotal |

## Qué demuestra este proyecto

- Investigación de incidentes a partir de logs en bruto: JSON, SQLite y `eve.json` de Suricata.
- Correlación de fuentes (honeypot, IDS y fingerprinting pasivo) para atribuir un evento con confianza.
- Consultas KQL en Kibana y procesado con `jq` y Python.
- Mapeo a MITRE ATT&CK con status (observado o capacidad) y nivel de confianza justificado.
- Recomendaciones de prevención, detección y respuesta para cada campaña.

## Privacidad y seguridad

- Las IPs de origen aparecen truncadas (`61.246.x.x`) o con alias (`IP-DIO-01`). La IP del honeypot no aparece.
- El repositorio no contiene logs en bruto ni binarios maliciosos, solo hashes.
- Las URLs de descarga, si aparecen, van desactivadas (`hxxp://`, `[.]`).

## Autor

**Daniel Fadrique** · SOC Analyst

[LinkedIn](https://www.linkedin.com/in/TU_PERFIL) · [GitHub](https://github.com/DanielFadrique)

Certificación BTL1

## Licencia

Contenido bajo [CC BY 4.0](LICENSE): puedes reutilizarlo citando la fuente.
