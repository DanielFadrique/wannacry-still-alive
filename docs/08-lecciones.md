# Conclusiones y lecciones aprendidas

## Sobre las amenazas

1. **Las amenazas antiguas siguen vivas.** WannaCry (2017) y bots tipo Mirai (2016) siguen propagándose en 2026 desde equipos que nadie ha parcheado.
2. **El volumen no indica peligrosidad.** La IP más ruidosa del honeypot (11.048 conexiones) no consiguió nada; la que entregó WannaCry hizo 5. Priorizar alertas solo por volumen habría ocultado lo importante.
3. **Casi todo está automatizado.** Ritmos de metrónomo, comandos enviados en milisegundos y diccionarios fijos: ninguno de los casos analizados muestra a una persona al teclado.
4. **Las IPs atacantes suelen ser víctimas.** Equipos Windows infectados, routers con credenciales de fábrica y dispositivos Android: la mayoría del tráfico viene de máquinas comprometidas, no de los operadores de las campañas. El [OSINT](07-osint.md) de las tres IPs de los casos apunta en la misma dirección.
5. **Las credenciales de fábrica y los patrones de teclado siguen siendo lo primero que prueban los bots** (`gpon/gpon`, `Admin/Admin`, `!QAZ2wsx`).

## Sobre la detección

6. **Suricata no detectó la explotación de MS17-010.** Con ~69.000 reglas cargadas, la semana terminó con 4.113 alertas y ninguna firma de exploit. Hay que revisar si las reglas de MS17-010 están activas y si dependen de respuestas que Dionaea no emula. Un IDS con muchas reglas no garantiza detectar un ataque conocido.
7. **El honeypot de Telnet no supera la comprobación de Mirai.** El bot comprueba con BusyBox que el dispositivo es real y se va antes de descargar. Si se quieren capturar muestras, Cowrie puede configurarse para responder a esa prueba.

## Sobre el método

8. **Kibana no lo es todo.** La captura de WannaCry no estaba en Elastic: solo en `dionaea.sqlite`. Conocer dónde guarda cada herramienta sus datos fue la clave de la investigación.
9. **Los recuentos de Kibana mezclan sensores.** Una IP con unos 90.000 eventos en Discover tenía 11.048 en Dionaea; el resto eran Suricata, P0f, etc. Por eso una sola IP puede superar el total de ~83.000, que solo cuenta eventos de los honeypots.
10. **El panel lateral de Discover calcula sobre una muestra.** Para cifras reales hay que usar *Visualize* o los logs en bruto.
11. **Filtrar por tipo de evento puede ocultar pasos.** Ver solo los comandos de Adbhoney escondía las subidas de ficheros y rompía la cronología.
12. **La rotación de logs limita lo que se puede investigar.** Los logs locales conservan unos 8 días: hay que exportarlos cada semana.
13. **Correlacionar fuentes da confianza.** La atribución de WannaCry es fuerte porque coinciden la base de datos de Dionaea, el tamaño del flujo en Suricata, la huella SMB y P0f.
14. **Comprobar un indicador antes de darlo por bueno.** La palabra `SAEXRG` del bot de Cowrie parecía la firma de una variante, pero al buscarla en toda la semana resultó ser aleatoria: 53 IPs usan la misma plantilla de comandos, cada una con su palabra. El indicador útil era la plantilla, no la palabra.

## Sobre la publicación

15. **La anonimización tiene que cubrir todos los campos.** La IP del honeypot aparece en `dest_ip` de Suricata y dentro de rutas SMB como `\\<IP>\IPC$`, campos que un script pensado para otros logs no cubría.

## Qué haría diferente

- Exportar los logs y `dionaea.sqlite` cada día desde el primer momento.
- Revisar la configuración de reglas de Suricata antes de exponer el honeypot.
- Documentar el diario del experimento (reinicios, cambios) en tiempo real.
- Ampliar a 30 días para tener más variedad y comparar semanas.

---

[← Volver al README](../README.md)
