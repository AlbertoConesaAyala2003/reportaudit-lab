# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Alberto Conesa 
- **Repositorio:** https://github.com/AlbertoConesaAyala2003/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04 LTS — Python 3.12.3

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | buscar_reportes_cliente | 41-42 | Posible inyección SQL al concatenar nombre_cliente en la consulta | parámetro cliente de la URL | cursor.execute(query)
| 2 | convertir_a_pdf | 50-51 | Posible inyección de comandos al construir un comando del sistema con nombre_archivo | parámetro archivo de la URL | os.system(comando)
| 3 | cargar_configuracion | 33 | Posible carga YAML insegura al usar yaml.Loader | contenido de config.yaml | yaml.load(f, Loader=yaml.Loader)
| 4 | hash_password_legacy | 57 | Hash de contraseña débil al usar MD5 sin salt | parámetro password | hashlib.md5(password.encode()).hexdigest()
| 5 | Constantes globales | 21-22 | Credenciales expuestas al estar escritas directamente en el código | valores hardcodeados en el código | NOTIFICATION_API_KEY y SMTP_PASSWORD

**Impacto en el negocio:**
**1. Inyección SQL:** un atacante podría acceder o manipular los reportes almacenados en la base de datos de clientes.
**2. Inyección de comandos:** un atacante podría ejecutar comandos en el sistema donde se ejecuta ReportAudit y comprometer el servidor. 
**3. YAML inseguro:** si el archivo de configuración fuera manipulado, podría procesar contenido malicioso y comprometer el sistema donde se ejecuta ReportAudit.
**4. Hash de contraseña débil:** si se filtraran los hashes de las contraseñas, un atacante tendría más facilidad para obtener las contraseñas originales.
**5. Credenciales expuestas:** si alguien accede al código, podría obtener la clave de la API de notificaciones y la contraseña SMTP, comprometiendo los servicios externos asociados.

**Síntoma observado:** al consultar el cliente `o'brien_ltd`, el servicio devuelve `500 Internal Server Error` y en la terminal aparece `sqlite3.OperationalError: near "brien_ltd": syntax error`.

**SonarQube Cloud**
- **Organization Key:** albertoconesaayala2003
- **Project Key:** AlbertoConesaAyala2003_reportaudit-lab

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (L) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | X | X | ✓ S3649 | ✓ py/sql-injection | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | X | X | ✓ S2076 | ✓ py/command-line-injection | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | X | X | ✗ | ✗ | ✓ avoid-pyyaml-load | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ S4790 | ✓ S4790 | ✓ S4790 | ✓ py/weak-sensitive-data-hashing | ✓ insecure-hash-algorithm-md5, md5-used-as-password | n/a |
| H5 Clave de API escrita en el código | ✓ | X | X | ✗ | ✗ | ✗ | ✗ |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ S2068 | ✓ S2068, S7552 | ✓ S2068, S7552 | ✗ | ✗ | ✗ |

**G.8 — Primera auditoría de main.** En la [ejecución del commit 67981f7](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45596434024), ambos trabajos terminaron correctamente. SonarQube registró seis vulnerabilidades y cero Security Hotspots. Además de las reglas de la matriz, señaló S4502 en `app/servicio.py:25`. CodeQL registró cuatro resultados, incluido `py/clear-text-logging-sensitive-data` en `app/reporte_auditoria.py:62`. Este último señala el registro de datos sensibles. H5 y H6 evalúan credenciales escritas en el código.

**Conclusión de la matriz (L).** Ningún escáner cubrió los seis hallazgos manuales. Semgrep señaló la carga insegura de YAML que CodeQL y SonarQube Cloud pasaron por alto. La revisión manual identificó ambas credenciales y Trivy no emitió alertas de secretos. CodeQL también señaló el registro de datos sensibles en la línea 62, fuera de los seis hallazgos manuales.

---

## Parte I — Dependabot

Tras la fusión del [PR #17](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/17), Dependabot abrió 13 alertas sobre `requirements.txt`. El origen de cada paquete se comprobó en las anotaciones `# via` del manifiesto.

| Paquete | Origen | Versión en main | Alertas abiertas | Versión propuesta en el PR #19 |
|---|---|---|---:|---|
| Flask | Directa, fijada en `requirements.in` | 3.0.0 | 1 | 3.1.3 |
| Jinja2 | Transitiva, vía Flask | 3.1.2 | 5 | 3.1.6 |
| Werkzeug | Transitiva, vía Flask | 3.0.1 | 7 | 3.1.9 |

La [alerta #1](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/security/dependabot/1), de severidad media, corresponde a CVE-2024-22195 / GHSA-h5c8-rqwp-cp95. Jinja2 permite inyectar atributos HTML cuando una plantilla usa claves controladas por el usuario en el filtro `xmlattr`. La versión fijada, 3.1.2, está en el intervalo afectado (anterior a 3.1.3). La primera versión corregida para este aviso es 3.1.3.

El [PR agrupado #19](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/19) incluye notas de versión de los tres paquetes. Modifica `requirements.in` para actualizar Flask y `requirements.txt` para reflejar la resolución, que también cambia las versiones de Blinker e ItsDangerous. Pasaron [SonarQube Cloud y CodeQL](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45605900107). El PR queda abierto para la parte M. El [PR #18](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/18) corresponde a la actualización de versión de `actions/checkout`.

## Parte J — Instalación y verificación de herramientas

En Ubuntu 24.04 (`linux/amd64`), el instalador descargó las versiones fijadas mediante curl y comparó el SHA-256 de cada archivo comprimido con el publicado en su misma release. Las tres sumas coincidieron antes de extraer los ejecutables en `tools/`.

| Ejecutable | Versión comprobada con `--version` | SHA-256 del archivo descargado |
|---|---|---|
| Syft | 1.52.0 | `caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d` |
| Grype | 0.119.0 | `3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b` |
| Trivy | 0.74.0 | `2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a` |

## Parte K — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | Flask 3.0.0 y PyYAML 6.0.3 |
| Componentes Python en el SBOM | 9 paquetes PyPI. A los dos directos se suman Blinker, Click, Colorama, ItsDangerous, Jinja2, MarkupSafe y Werkzeug. El manifiesto condiciona Colorama a Windows. |
| Otros componentes y origen | 4 acciones en `.github/workflows/cadena-suministro.yml`: checkout v6, sonarqube-scan-action v7, codeql-action/init v4 y codeql-action/analyze v4. Syft también registra el workflow y `requirements.txt` como dos componentes de tipo archivo. |
| Formato y versión de especificación | [CycloneDX 1.7](evidencias/sbom.cyclonedx.json), generado con Syft 1.52.0 sobre la copia local de `main` en `7156858`, excluidos `venv/` y `tools/`. |

---

## Parte K — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2024-34069 / GHSA-2g68-c3qc-8985](https://github.com/advisories/GHSA-2g68-c3qc-8985) | Alta | 3.0.3 | El arranque documentado desactiva el depurador (servicio.py:64). | VEX y actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2024-49767 / GHSA-q34m-jh98-gwm2](https://github.com/advisories/GHSA-q34m-jh98-gwm2) | Media | 3.0.6 | Las rutas usan GET y request.args (servicio.py:28–58). No se observa análisis de formularios multipart en estas rutas. | Actualizar con #19 en M. |
| jinja2 | 3.1.2 | Transitiva vía Flask | [CVE-2024-34064 / GHSA-h75v-3vvj-5mfj](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) | Media | 3.1.4 | Las rutas devuelven JSON. No se usan claves externas en el filtro xmlattr de Jinja. | Actualizar con #19 en M. |
| jinja2 | 3.1.2 | Transitiva vía Flask | [CVE-2024-22195 / GHSA-h5c8-rqwp-cp95](https://github.com/advisories/GHSA-h5c8-rqwp-cp95) | Media | 3.1.3 | Las rutas devuelven JSON. No se pasan claves de atributos de usuario al filtro xmlattr. | Actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j](https://github.com/advisories/GHSA-f9vj-2wh5-fj8j) | Media | 3.0.6 | Afecta a safe_join en Windows con Python anterior a 3.11. La práctica utiliza Ubuntu y Python 3.12. | Actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2026-27199 / GHSA-29vq-49wr-vm6x](https://github.com/advisories/GHSA-29vq-49wr-vm6x) | Media | 3.1.6 | El caso requiere nombres de dispositivo de Windows en rutas con varios segmentos. El despliegue auditado usa Linux. | Actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2025-66221 / GHSA-hgf8-39gv-g3f2](https://github.com/advisories/GHSA-hgf8-39gv-g3f2) | Media | 3.1.4 | La apertura de nombres de dispositivo mediante safe_join requiere Windows. El despliegue usa Linux. | Actualizar con #19 en M. |
| jinja2 | 3.1.2 | Transitiva vía Flask | [CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h](https://github.com/advisories/GHSA-q2x7-8rv6-6q7h) | Media | 3.1.5 | Las rutas no procesan plantillas de terceros en el sandbox de Jinja. | Actualizar con #19 en M. |
| jinja2 | 3.1.2 | Transitiva vía Flask | [CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7](https://github.com/advisories/GHSA-cpwx-vrp4-4pq7) | Media | 3.1.6 | Las rutas JSON no aceptan plantillas Jinja de terceros ni invocan el filtro attr en un sandbox. | Actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2026-21860 / GHSA-87hc-h4r5-73f7](https://github.com/advisories/GHSA-87hc-h4r5-73f7) | Media | 3.1.5 | El tratamiento afectado de nombres de dispositivo con extensiones o espacios es específico de Windows. El despliegue usa Linux. | Actualizar con #19 en M. |
| werkzeug | 3.0.1 | Transitiva vía Flask | [CVE-2026-102598 / GHSA-g6x2-hccm-hh4m](https://github.com/advisories/GHSA-g6x2-hccm-hh4m) | Media | 3.1.9 | El caso exige NTFS y nombres de dispositivo de Windows. El servicio auditado corre en Ubuntu. | Actualizar con #19 en M. |
| jinja2 | 3.1.2 | Transitiva vía Flask | [CVE-2024-56201 / GHSA-gmj6-6f8f-6699](https://github.com/advisories/GHSA-gmj6-6f8f-6699) | Media | 3.1.5 | El servicio no compila plantillas Jinja cuyo nombre y contenido controle el cliente. | Actualizar con #19 en M. |
| flask | 3.0.0 | Directa | [CVE-2026-27205 / GHSA-68rp-wp8r-4726](https://github.com/advisories/GHSA-68rp-wp8r-4726) | Baja | 3.1.3 | Las rutas devuelven JSON y no consultan la sesión. Falta el acceso a sesión que afecta a Vary: Cookie. | Actualizar con #19 en M. |

**Comparación con Dependabot (I).** Al emparejar los GHSA de [Grype](evidencias/grype-antes.txt) con los CVE de las 13 alertas de GitHub, coinciden los 13 avisos y sus paquetes. El triage describe el servicio en Ubuntu 24.04 con Python 3.12 y las rutas de `app/servicio.py:28–64`. Las versiones siguen afectadas según el inventario, por lo que se mantiene la actualización prevista en el PR #19.

**[Documento VEX](evidencias/reportaudit.openvex.json).** En el arranque documentado de ReportAudit, `app/servicio.py:64` fija `debug=False`. El depurador afectado por CVE-2024-34069 queda fuera de esa ejecución.

---

## Parte L y M — Antes y después

**M.2 — Verificación local.** El cliente de pruebas de Flask devolvió HTTP 200 y dos reportes para `acme_corp`, y HTTP 200 y un reporte para `o'brien_ltd`. La conversión de `informe.html` respondió 200 con el nombre de salida previsto. En este Ubuntu falta `wkhtmltopdf` y el servicio avisó de que no generó el PDF. El nombre `informe final.html` obtuvo 400. Se comprobó la lista de argumentos al conversor con un sustituto de prueba. Dos hashes de una misma contraseña tuvieron sales distintas y el derivado se verificó con 600 000 iteraciones. El registro de notificaciones omitió el valor de prueba de la clave. `pre-commit run --all-files` terminó en `Passed`.

**L — Escaneo del sistema de archivos.** [Trivy 0.74.0](evidencias/trivy-antes.txt) analizó dependencias y secretos con `venv/` y `tools/` excluidos. Encontró 13 vulnerabilidades en `requirements.txt` (1 alta, 11 medias y 1 baja). Coinciden con Grype los CVE, los paquetes y las primeras versiones corregidas. El escaneo de secretos no señaló las credenciales de H5 y H6.

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (188 reglas sobre 3 archivos) | 0 bloqueantes (Semgrep pasó sobre todos los archivos aplicables) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 | 0 (las cuatro en estado Fixed) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 | 0 (S4502 corregido en `9554e88`) |
| Security Hotspots por revisar en SonarQube Cloud | 0 | 0 |
| Vulnerabilidades de Grype sobre el SBOM | 13 | 0 |
| Vulnerabilidades de Trivy en requirements.txt | 13 | 0 |
| Alertas abiertas de Dependabot | 13 | 0 (alertas #1–#13 corregidas) |

**M.5.** El [PR #19](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/19) actualizó las versiones fijadas en los manifiestos. GitHub marcó las 13 alertas de Dependabot como `fixed`. En el entorno virtual de Ubuntu se verificaron Flask 3.1.3, Jinja2 3.1.6 y Werkzeug 3.1.9. `pip check` confirmó la compatibilidad de las dependencias y pasaron las siete pruebas. También pasaron [los dos trabajos SAST en main](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45706093189). CodeQL cerró sus alertas al cambiar el código en el PR #20; Dependabot cerró las suyas al detectar las versiones corregidas tras el PR #19.

**M.4.** En el [análisis de main tras la fusión](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45684686920) pasaron los dos trabajos SAST. Tras el PR #20, SonarQube mantenía abierto el [aviso S4502 sobre protección CSRF](https://sonarcloud.io/project/issues?id=AlbertoConesaAyala2003_reportaudit-lab&open=AaDtBn8WHLoqijiD9cDJ). Este hallazgo ya aparecía en G.8.

---

**Seguimiento de M.4.** El GET de conversión podía escribir un PDF. En la rama `fix/proteccion-csrf`, GET presenta una confirmación y solo el POST con token CSRF de la misma sesión invoca el conversor. Pasaron diez pruebas, Semgrep y la verificación de dependencias. En el [PR #21](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/21), commit `88bb613`, se solicitó la revisión de JuanAliaga-dev. Los dos trabajos SAST y el check de CodeQL pasaron. SonarQube midió 100 % de cobertura nueva y bloqueó su control de calidad por S6350 en `app/reporte_auditoria.py:57` (nombre enviado por formulario al conversor). Ireneyss aprobó `88bb613`. En `e7b56ef`, el conversor selecciona el archivo HTML en el directorio local y descarta enlaces simbólicos de entrada. Pasaron las once pruebas, Semgrep y los [cuatro checks del PR](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45780923045). Ireneyss también aprobó `e7b56ef`. El PR se fusionó en `9554e88` el 26/11/2026 a las 08:24 UTC. En el [análisis de main](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45782961849), SonarQube cerró S4502 como `FIXED` y registró cero vulnerabilidades abiertas y cero hotspots pendientes. CodeQL mantuvo las cuatro alertas corregidas y cero abiertas. M.4 completado.

## Parte N — Evidencias tras la corrección

El 26/11/2026 se analizó el contenido confirmado de main en `9554e88`. Se extrajo una copia limpia para que los informes antiguos y las ediciones locales no alterasen la medición. Syft inventarió 15 componentes con identificador de paquete (10 de Python y 5 de GitHub Actions). Grype analizó ese inventario con la base del 26/11. Trivy analizó el árbol con los detectores de vulnerabilidades y secretos activados. Registró cero vulnerabilidades en el manifiesto y no emitió hallazgos de secretos. El hook de Semgrep pasó en el repositorio local. GitHub mostró cuatro alertas de CodeQL y trece de Dependabot corregidas. SonarQube Cloud mostró cero vulnerabilidades abiertas y cero hotspots pendientes en main.

| Evidencia | Antes | Después |
|---|---|---|
| Inventario CycloneDX | [SBOM inicial](evidencias/sbom.cyclonedx.json) | [SBOM final](evidencias/sbom-despues.cyclonedx.json) |
| Avisos sobre el inventario | [Grype inicial](evidencias/grype-antes.txt) | [Grype final](evidencias/grype-despues.txt) |
| Dependencias y secretos en archivos | [Trivy inicial](evidencias/trivy-antes.txt) | [Trivy final](evidencias/trivy-despues.txt) |

## Preguntas de comprobación (Sección 7 de la guía)

1. Windows aloja VS Code y el navegador. En Ubuntu están el repositorio local, Python, las herramientas y el servicio. Trabajar allí permite ejecutar la práctica con las rutas, permisos y programas de Linux. GitHub aloja el repositorio compartido, los Issues, las revisiones y los trabajos de integración.
2. ReportAudit declara Flask en requirements.in. Blinker aparece en el SBOM porque Flask lo necesita. El comentario «via flask» del fichero compilado explica por qué se instaló.
3. El origen es el punto por donde entra un dato y el destino es la operación sensible que lo recibe. En la versión inicial, servicio.py leía el cliente de la URL y buscar_reportes_cliente en reporte_auditoria.py lo incorporaba al texto que recibía cursor.execute.
4. El apóstrofo de o'brien_ltd cerraba la cadena SQL antes de tiempo. El error observado, junto con la concatenación visible en el código, mostraba que el cliente podía alterar la sintaxis. Al enlazarlo como parámetro, SQLite interpreta el nombre entero como dato.
5. Semgrep puede bloquear el commit en el equipo del autor. En H bloqueó tres hallazgos. El hook depende de la instalación local y de sus reglas. Los controles del PR vuelven a analizar el código compartido antes de fusionarlo.
6. Cada herramienta cubre reglas y tipos de evidencia distintos. En esta ejecución Semgrep señaló la carga YAML que CodeQL y SonarQube Cloud pasaron por alto. Ambos detectaron el flujo hacia SQL que Semgrep omitió. Trivy identificó las dependencias vulnerables y no señaló las dos credenciales.
7. CodeQL sigue flujos en el código y Dependabot compara las versiones declaradas con avisos conocidos. El PR #20 corrigió los flujos y el #19 cambió las versiones. Cada panel cerró sus propias alertas tras analizar main.
8. Quitar la cadena del código evita distribuirla en copias nuevas. Quien conserve una copia antigua puede seguir utilizándola mientras sea válida. Hay que revocarla en el proveedor, emitir otra y entregarla al servicio por un canal protegido. La rotación efectiva sigue pendiente de confirmación.
9. El VEX conserva el aviso y documenta su aplicabilidad a un producto concreto. Para CVE-2024-34069 se justificó que el arranque auditado de ReportAudit desactiva el depurador de Werkzeug. Un cambio en el despliegue obliga a revisar esa conclusión.
10. El instalador compara la huella SHA-256 del archivo descargado con la publicada para esa versión. Detecta una sustitución si la referencia es fiable. Si se compromete también el canal que publica la referencia, la coincidencia por sí sola no acredita la integridad del proceso de publicación.
11. Git conserva las versiones anteriores a la retirada de las credenciales. Un análisis del árbol actual y otro del historial cubren contenidos distintos. Revocar las credenciales cierra el riesgo de reutilización. En O se observaron cero hallazgos en app y dos en el historial con la regla propia antes de aplicar las excepciones.
12. En G había trece avisos de dependencias. Exigir pip-audit entonces habría bloqueado también correcciones independientes. Tras sanear las versiones en M, el control obligatorio de P detectó el retroceso deliberado de versión en el PR #25.
13. Dependabot avisa cuando relaciona una versión del repositorio con un aviso conocido. Un control obligatorio de pip-audit evalúa la propuesta antes de fusionarla y puede impedir que llegue a main.
14. Verificar la atestación vincula el archivo por su huella con una declaración firmada de procedencia del repositorio esperado. Una lista de sumas aislada puede sustituirse junto con el archivo. La procedencia tampoco garantiza que el programa carezca de vulnerabilidades. En R se verificaron las dos atestaciones y se rechazó una copia alterada.
15. El canal privado permite a los mantenedores evaluar el informe y preparar la corrección antes de divulgar detalles. SECURITY.md indica dónde informar, qué versiones se atienden y qué respuesta esperar.
16. Maintained mide señales de actividad durante una ventana de tiempo. Un laboratorio reciente puede puntuar bajo por su corta historia. Ese dato debe interpretarse con la antigüedad, la actividad esperada y los demás controles. Scorecard midió 0/10 en Maintained por la antigüedad del repositorio.
17. De las áreas planteadas en B5, hoy se pueden comprobar los análisis del commit publicado, el SBOM firmado, la actualización de dependencias, la política y el canal de divulgación. Quedan fuera la evaluación formal de riesgos y la documentación técnica completa. Para contrastar estos resultados con las herramientas o pruebas concretas que propusimos falta recuperar nuestra tabla B5 entregada.

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| [#1](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/1) | Adopt an international pull request template | JuanAliaga-dev aprobó el [PR #14](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/14) el 25/11/2026 a las 09:41 UTC. Se fusionó a las 09:54 UTC (`5a194e0`) y el Issue se cerró mediante `Closes #1`. |
| [#2](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/2) | Run SAST (SonarQube Cloud and CodeQL) on every pull request | [PR #15](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/15), commit `d0506c3`. El 25/11/2026 pasaron `SAST - SonarQube Cloud` y `SAST - CodeQL` en la [ejecución de GitHub Actions](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45594510469). G.6 verificado en GitHub: la protección de `main` exige ambos checks, rama actualizada, una aprobación y conversaciones resueltas. JuanAliaga-dev aprobó el commit `d0506c3` el 25/11/2026 a las 10:31 UTC. PR fusionado en `67981f7` el 25/11/2026 a las 10:35 UTC. GitHub cerró el Issue #2. |
| [#3](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/3) | Block insecure commits with a Semgrep pre-commit hook | [PR #16](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/16), commit `b14241f`. Hook local instalado. El commit de prueba quedó bloqueado con código 1 y HEAD siguió en `b14241f`. [Salida del hook con los identificadores de regla](evidencias/H3-commit-bloqueado.txt). [Imagen de la salida](evidencias/H3-commit-bloqueado.png). Los [dos checks SAST](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45597476542) pasaron. JuanAliaga-dev aprobó el commit `b14241f` el 25/11/2026 a las 10:49 UTC. PR fusionado en `57eb659` a las 10:51:41 UTC. GitHub cerró el Issue #3 a las 10:51:42 UTC. Parte H completada. La práctica se detiene al inicio de I. |
| [#4](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/4) | Enable Dependabot alerts and security updates | I.1: [PR #17](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/17), commit `ef87b53`, vinculado con `Refs #4`. Solo añade la configuración semanal de pip y GitHub Actions. Pasaron [SonarQube Cloud y CodeQL](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45599716022). JuanAliaga-dev aprobó el commit `ef87b53` el 25/11/2026 a las 11:01 UTC. Fusionado en `7156858` el 25/11/2026 a las 11:04 UTC. I.2 verificado: grafo de dependencias disponible, alertas activadas, actualizaciones de seguridad activas y agrupación activada. I.3 completado. [Cierre del Issue con la evidencia](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/4#issuecomment-7166082898) el 25/11/2026 a las 14:57 UTC. |
| #5 | Remediate the findings of the security audit | M.1–M.2 en la rama local `fix/auditoria-seguridad`. Consulta parametrizada, conversión con nombre validado y argumentos separados, carga segura de YAML, PBKDF2-SHA256 con sal aleatoria y credenciales procedentes del entorno. El registro solo indica si la clave está configurada. Rotación en los proveedores pendiente de confirmar. M.3: [PR #20](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/20), commit `719d2ed`, revisión solicitada a JuanAliaga-dev. En la [primera ejecución](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45644444130) pasaron los trabajos SAST, pero CodeQL señaló `py/polynomial-redos` y SonarQube indicó cobertura nueva del 0 % (mínimo 80 %). La validación alternativa sin expresión regular pasó 12 casos locales y Semgrep. El commit `549d78f` incorporó la corrección y siete pruebas automatizadas. SonarQube midió un 100 % de cobertura del código nuevo (mínimo 80 %) y CodeQL confirmó cero alertas nuevas. Pasaron los [cuatro checks](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45645667585). JuanAliaga-dev aprobó el commit `549d78f`. El PR se fusionó en `fb34ba4` el 25/11/2026 a las 19:23 UTC y GitHub cerró el Issue #5. |
| #6 | Upgrade the vulnerable dependencies | [PR #19](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/19) actualizado con main. GitHub muestra la aprobación de Ireneyss y los [cuatro checks en verde](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45704856679) para `73badd4`. Fusionado en `9e0d0cb` el 25/11/2026 a las 21:37 UTC. GitHub cerró el [Issue #6](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/6). |
| #7 | Publish the audit log and the before/after evidence | [PR #22](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/22) aprobado por Ireneyss y fusionado en 598357c. |
| [#8](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/8) | Detect ReportAudit credentials in the whole Git history | Ireneyss aprobó el [PR #23](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/23). Pasaron los cuatro controles. La fusión en `9062e22` cerró el Issue el 26/11/2026. |
| #9 | Make SCA and secret scanning required checks on main | [Cerrado con la evidencia de P.4](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/9#issuecomment-7192079749). |
| #10 | Publish a security policy and a private vulnerability reporting channel | [Cerrado el 26/11/2026](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/10#issuecomment-7195196580) tras publicar la política, activar el canal privado y completar ambos turnos del simulacro con Irene. |
| #11 | Release v1.0.0 with an SBOM and signed provenance | [Cerrado el 26/11/2026 con los resultados de R.3](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/11#issuecomment-7195876248). |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | Cerrado al fusionar el [PR #28](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/28), aprobado por Ireneyss. |
| #13 | Build the CRA evidence index | Expediente preparado para revisión externa. |

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

Gitleaks 8.30.1 instalado en Ubuntu después de comprobar la huella SHA-256 del paquete oficial: `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`. Escaneo del 26/11/2026 desde la revisión `598357c`. Se ocultaron los valores en todas las ejecuciones.

| Escaneo | Comando (con `--redact`) | Hallazgos | Origen |
|---|---|---:|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | Ninguno |
| Historial, reglas por defecto | `gitleaks git .` | 1 | `26c1503`, app/reporte_auditoria.py:21 (generic-api-key) |
| Historial, regla propia y reglas por defecto | `gitleaks git . -c .gitleaks.toml` | 2 | `26c1503`, app/reporte_auditoria.py:21–22 (clave de notificaciones y contraseña SMTP) |
| Código actual, con regla propia | `gitleaks dir app -c .gitleaks.toml` | 0 | Ninguno |
| Historial tras registrar las excepciones | `gitleaks git . -c .gitleaks.toml --redact` | 0 | Dos excepciones limitadas al commit de importación |

Las versiones anteriores conservan las asignaciones que la corrección de M retiró del código. La revocación en el proveedor invalida las copias existentes. El [informe redactado](evidencias/gitleaks-historial.json) conserva las referencias a los dos hallazgos.

Por indicación del autor, las dos cadenas se tratan como ficticias a efectos de la práctica. Se desconoce si fueron válidas o si se revocaron en algún proveedor. Tras registrar sus dos huellas, Gitleaks terminó con código 0 en el historial y en el directorio de la aplicación. Una asignación SMTP ficticia en un archivo temporal produjo un hallazgo y código 1.

### P. Puertas obligatorias en main

P.1: se prepararon los trabajos de pip-audit y Gitleaks en la rama `ci/puertas-sca-secretos`. La acción de PyPA v1.1.0 recibe `--disable-pip` mediante su entrada de argumentos adicionales. P.2: el 26/11/2026 GitHub mostró tanto el escaneo de secretos como la protección de los envíos en estado `enabled`. Antes de P.4, la protección de main exige los dos trabajos SAST. La prueba del PR borrador corresponde a P.3.

| Check | ¿Exigido en main? | Resultado en el PR de prueba |
|---|---|---|
| SAST - SonarQube Cloud | Sí | Falló al instalar las dependencias antes del análisis. Flask 3.1.3 exige Werkzeug ≥3.1.0. |
| SAST - CodeQL | Sí | Pasó. |
| SCA - pip-audit | Sí | Falló con código 1. Ocho identificadores de aviso para Werkzeug 3.0.1. |
| Secretos - Gitleaks | Sí | Pasó. |

P.4: el 26/11/2026 se verificaron en GitHub los cuatro controles obligatorios de la tabla, una aprobación de un compañero y la exigencia de que la rama esté actualizada antes de fusionarse. La protección de los envíos y el escaneo de secretos estaban activos. Se eliminó la rama de prueba local y remota y se cerró el Issue #9.

Ireneyss aprobó el [PR #24](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/24). Los cuatro trabajos pasaron y la fusión incorporó los controles en `4456fdd`. El [borrador #25](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/25) cambió únicamente Werkzeug de 3.1.9 a 3.0.1 y se cerró sin fusión. El [registro original de pip-audit](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45819581810/job/139908039520) y su extracto visual incluido en el material local de evaluación recogen los identificadores y sus versiones corregidas. En main se mantuvo Werkzeug 3.1.9.

### Q. Divulgación coordinada (simulacro)

Q.1: Ireneyss aprobó el [PR #26](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/26). Pasaron los seis controles y se verificó la [política publicada en main](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/blob/main/SECURITY.md) tras la fusión en `fa6d63a`. Q.2: el 26/11/2026 se activó el [canal privado de ReportAudit](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/security/advisories/new) y se confirmó mediante la API de GitHub (`enabled: true`).

Q.3, turno como investigador (26/11/2026): AlbertoConesaAyala2003 remitió el informe privado al repositorio de Ireneyss. Irene lo aceptó y respondió en la conversación privada. Se verificó el estado de borrador en GitHub. En la comprobación de ese día, el repositorio de Alberto todavía no había recibido el informe recíproco.

Q.3, turno como responsable: más tarde ese mismo día llegó el informe de Irene. Alberto lo aceptó como borrador y agradeció en inglés la comunicación en el hilo privado. Se comprobó su crédito como informante. El aviso permanece en borrador, sin publicación ni CVE. La captura se guardó localmente para el documento de evidencias.

- Informante: Ireneyss.
- Identificador del borrador: GHSA-hh77-gff8-wmjr.
- Severidad: alta, CVSS 3.1 de 7,5. Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`. La evaluación supone un despliegue accesible por red y considera la posible lectura de reportes de otros clientes. El arranque local usa loopback. No se acreditó modificación o borrado de datos.
- Debilidad: CWE-89 (inyección SQL). La corrección enlaza el nombre del cliente como parámetro de la consulta.
- Paquete: `reportaudit` (pip). Versiones afectadas: anteriores a 1.0.0. Versión corregida indicada en el borrador: 1.0.0.

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | Paquete e inventario: OK. |
| Procedencia SLSA | `gh attestation verify` | Código 0 para el workflow de publicación, la etiqueta v1.0.0 y el commit 211d587. |
| SBOM atestado | `gh attestation verify --predicate-type https://cyclonedx.org/bom` | Código 0. El inventario descargado coincide con el contenido de la declaración firmada. |
| Archivo alterado | `gh attestation verify` sobre la copia modificada | Código 1. GitHub no encontró una atestación para la nueva huella. |

Ireneyss aprobó el [PR #27](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/27). La [ejecución de publicación](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45845814575) generó los cinco archivos de la [release v1.0.0](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/releases/tag/v1.0.0). Se descargaron en un directorio independiente y se verificaron con GitHub CLI 2.106.0. El [resumen de verificación](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/issues/11#issuecomment-7195876248) confirma que se rechazó la copia alterada. Las sumas detectan cambios respecto al manifiesto, la procedencia vincula el paquete con el workflow y el SBOM firmado vincula el inventario con ese paquete. Un workflow de origen comprometido podría firmar un paquete defectuoso y superar estas comprobaciones.

### S. Madurez (OpenSSF Scorecard)

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | 7 | Medición publicada para `e8e0955` el 26/11/2026. Seis controles empatan con la nota mínima. |
| CII-Best-Practices | 0 | No se detectó participación en el programa de insignias de buenas prácticas de OpenSSF. |
| Contributors | 0 | Scorecard identificó cero empresas u organizaciones contribuyentes. Esta métrica mide diversidad organizativa. |
| Fuzzing | 0 | El análisis no encontró pruebas automatizadas de fuzzing. |
| License | 0 | El análisis no encontró un archivo de licencia en el repositorio. |
| Maintained | 0 | El repositorio se creó en los últimos 90 días. Su historial aún es corto para evaluar la continuidad del mantenimiento. |
| Pinned-Dependencies | 0 | Las acciones se referencian con etiquetas, como `actions/checkout@v6`, que pueden apuntar a otro commit con el tiempo. |

La [ejecución en main](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45847450767) publicó el informe en Code Scanning y en el [visor de OpenSSF](https://scorecard.dev/viewer/?uri=github.com/AlbertoConesaAyala2003/reportaudit-lab). Dos controles quedaron sin puntuación: el token de Scorecard no pudo leer la protección clásica de ramas y Packaging no reconoció el workflow de empaquetado. Signed-Releases obtuvo 8/10 y sí reconoció un artefacto firmado en la única release.

Para elegir una dependencia, Code-Review resulta útil porque indica cuántos cambios tuvieron una segunda revisión: en esta medición fueron 12 de 13 (9/10). Maintained es el más fácil de malinterpretar aquí: su 0 responde a la antigüedad del proyecto y, por sí solo, no demuestra abandono.

**S.3 — Comparación tras fijar las acciones de publicación.** Irene aprobó el [PR #29](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/pull/29), fusionado el 27/11/2026. En la [ejecución de Scorecard sobre `d00bb39`](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/actions/runs/45965406875), Pinned-Dependencies subió de 0 a 1/10 y la puntuación global de 7,0 a 7,1/10. El análisis reconoció las cuatro referencias fijadas en el workflow de publicación: tres usos de acciones de GitHub y uno de terceros. Al evaluar todo el repositorio encontró otras catorce referencias por etiqueta en `cadena-suministro.yml` y `scorecard.yml`, además de una instalación con pip sin hashes.

### T. Expediente de evidencias

El [expediente de v1.0.0](cra/expediente-evidencias.md) recoge doce filas. Se comprobaron diecinueve destinos públicos y el borrador con acceso de colaborador. La revisión externa debe documentarse en el PR final.
