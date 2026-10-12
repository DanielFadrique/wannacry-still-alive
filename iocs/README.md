# Indicadores de compromiso (IOCs)

Muestras de malware capturadas por los honeypots entre el 26/09/2026 y el 03/10/2026. Solo se publican los hashes: los binarios no están en el repositorio. Detecciones de VirusTotal consultadas el 12/10/2026; pueden cambiar con nuevos análisis.

| SHA-256 | Tipo | Familia | Honeypot | VirusTotal | Caso |
|---|---|---|---|---|---|
| `c05e2dab77349cd639aa837e7e121710b8a0718d8fc93fb4cc6458ae90e5c597` | DLL Windows | WannaCry (ransomware y gusano, MS17-010) | Dionaea | [67/71](https://www.virustotal.com/gui/file/c05e2dab77349cd639aa837e7e121710b8a0718d8fc93fb4cc6458ae90e5c597) | [Caso 2](../docs/04-caso-dionaea.md) |
| `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` | APK Android | App maliciosa com.ufo.miner (minero) | Adbhoney | [49/68](https://www.virustotal.com/gui/file/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257) | [Caso 1](../docs/03-caso-adbhoney.md) |
| `71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5` | ELF ARM | Gusano de minería que se propaga por ADB | Adbhoney | [39/64](https://www.virustotal.com/gui/file/71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5) | [Caso 1](../docs/03-caso-adbhoney.md) |

**MD5 de WannaCry:** `ae12bb54af31227017feffd9598a6f5e`. Es el que registra Dionaea en `dionaea.sqlite` y el que permitió relacionar la muestra con su conexión de origen.

## Formato para herramientas

[`hashes.csv`](hashes.csv) contiene los mismos datos en CSV, listo para importar en un SIEM, una plataforma de threat intelligence o una lista de bloqueo.

---

[← Volver al README](../README.md)
