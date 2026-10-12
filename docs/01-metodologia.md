# Metodología

## Despliegue

| Aspecto                   | Valor                                                                               |
| ------------------------- | ----------------------------------------------------------------------------------- |
| Plataforma                | T-Pot (tipo Hive) en un VPS dedicado                                                |
| Proveedor y región        | _Hostinger, alojado en Alemania_                                                    |
| Periodo analizado         | 26/09/2026 – 03/10/2026 (UTC). Primeros eventos el 25/09 a las 20:20 UTC            |
| Puertos de administración | SSH por 64295 e interfaz web por 64297, accesibles solo desde mis IPs de confianza  |
| Resto de puertos          | 1-64000 se quedan abiertos para poder recibir los ataques (el resto queda bloqueado) |

**Honeypots analizados en detalle:** 

- Adbhoney (ADB, TCP/5555) 
- Cowrie (SSH y Telnet) 
- Dionaea (SMB, MSSQL y servicios de Windows).
  
**Logs de apoyo:** 

- Suricata (IDS) 
- P0f (fingerprinting pasivo del sistema operativo).

## Fuentes de datos

| Fuente                                                           | Para qué se usó                                                       |
| ---------------------------------------------------------------- | --------------------------------------------------------------------- |
| Kibana (Dashboards/Discover)                                     | Exploración, recuentos y consultas KQL                                |
| Logs en bruto de cada honeypot (`~/tpotce/data/<honeypot>/log/`) | Reconstruir sesiones completas, sin los límites de muestreo de Kibana |
| `dionaea.sqlite`                                                 | Relacionar cada fichero capturado con la conexión que lo entregó      |
| `eve.json` de Suricata                                           | Tamaño de cada conexión, comandos SMB y alertas                       |
| P0f                                                              | Sistema operativo estimado del origen                                 |
| VirusTotal                                                       | Identificar el malware por su hash                                    |

Los logs rotan cada día y se conservan unos 8 ficheros. Por eso la extracción une el log actual con sus rotaciones `.gz`.

## Proceso de análisis

1. **Panorama:** recuentos por honeypot, servicio e IP en los Dashboards creados por T-Pot al instalarlo.
2. **Elegir una campaña por honeypot:** una IP con actividad completa y/o interesante, no necesariamente tiene que ser la más ruidosa.
3. **Extraer todos sus eventos:** logs en bruto, filtrar por tipo, y reconstruir la sesión en orden.
4. **Correlacionar:** Suricata y P0f por IP, puerto de origen y hora.
5. **Interpretar cada paso:** qué hace el comando y qué busca vulnerar el atacante.
6. **Mapeo a MITRE ATT&CK** con status y confianza ([criterios](06-mapeo-mitre.md#criterios-de-mapeo)).

## Status y confianza

| Status | Significado |
|---|---|
| **Observado** | El honeypot o un sensor lo registró |
| **Capacidad** | La muestra puede hacerlo, pero no ocurrió (los honeypots no ejecutan el malware) |
| **Hipótesis** | Deducción razonable sin prueba directa |

**Confianza:** 

- Alta (varias pruebas coinciden o no hay otra lectura posible) 
- Media (encaja, pero con matices o aproximaciones)  
- Baja (deducción débil o intención incierta).

## Anonimización

- IPs de origen sustituidas por alias (`IP-DIO-01`) o truncadas (`61.246.x.x`). La correspondencia real solo se guarda en local.
- Sin binarios maliciosos: solo hashes.

## Limitaciones

- **Un solo VPS, una región y una semana.** Las cifras no son representativas de Internet en general.
- **Los honeypots no ejecutan el malware.** El impacto final (cifrado, minería, DDoS) solo se puede afirmar como capacidad.
- **Las "credenciales correctas" dependen de la configuración**: Cowrie, por ejemplo, acepta muchas.
- **Kibana mezcla sensores:** el recuento de una IP incluye eventos de Suricata, P0f, etc. Para cifras por honeypot se usan también los logs en bruto.
- **Atribución:** una IP atacante puede ser simplemente un equipo infectado, no el responsable detrás de la campaña.


---

[← Volver al README](../README.md)
