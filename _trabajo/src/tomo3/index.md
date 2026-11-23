# Reversing en Windows — Edición Libre y Abierta
## Tomo III: LLVM, Rust, Contenedores y Reversing con IA Local
*(Revisión 5.5 / Trilogía Consolidada)*

---

### Ficha Técnica del Volumen

- **Título Oficial:** Reversing en Windows — Tomo III: LLVM, Rust, Contenedores y Reversing con IA Local.
- **Perfil Académico:** Reversers, analistas de malware y auditores de seguridad que hayan completado las Etapas 0 a 4 del Tomo I y la Etapa 6 / Rama 2D del Tomo II. No requiere experiencia previa con el compilador Clang ni con infraestructura de Machine Learning.
- **Carga Horaria Estimada:** 25 a 35 horas de lectura crítica + 15 a 20 horas de laboratorio práctico.
- **Presupuesto Editorial:** 54 páginas consolidadas (27 hojas físicas a doble faz para encuadernación Ring Wire 3:1 de 14.3 mm, volumen completo de cierre).
- **Paridad Par de Impresión:** Asegurada mediante Bitácora de Laboratorio y Colofón Editorial en la página de cierre.

---

### Puerta de Salida Declarada

> *«Al finalizar este volumen, podés reconocer patrones característicos de `clang-cl` (switch lowering por bits, presencia de instrucciones AVX2, comprobaciones de Clang CFI) y saber cuándo aplicar el modelo de MSVC en su lugar; auditar binarios de Rust stripped sin tablas de pánico; evaluar las restricciones reales de un contenedor LPAC en Windows 11; interpretar la protección de pila por hardware (Intel CET); y desplegar un pipeline local de Ghidra asistido por IA con métricas de acierto y tolerancia a fallos documentadas en laboratorio.»*

---

### Declaración de Alcance, Límites y Pendientes Heredados

#### Lo que este volumen NO cubre
1. **Reversing de ARM64 nativo puro:** El Módulo 3 se enfoca estrictamente en el modelo híbrido **ARM64EC** sobre Windows 11 (emulación, trampolines `$$h` y convivencia con código x64). Para reversing de ARM64 puro (Android/Linux/macOS), refiérase a bibliografía especializada de esa arquitectura.
2. **Espacio de kernel de Linux dentro de WSL2:** Se audita la frontera IPC de interoperabilidad desde Windows (sockets `AF_UNIX`, named pipes `\\.\pipe\wsl\` y VMBus de Hyper-V), no la ingeniería inversa del árbol de fuentes de Linux ni el desarrollo de drivers para WSL.
3. **Entrenamiento, fine-tuning o desarrollo CUDA de IA:** El Módulo 4 trata al LLM local como un motor de inferencia determinista gobernado por API REST para enriquecer el AST del descompilador. No es un manual de Machine Learning ni de computación tensorial.
4. **Sustitución del criterio analítico humano:** Ninguna sugerencia de renombrado o tipado generada por IA se acepta en el informe de auditoría sin la validación empírica de sus referencias cruzadas contra las APIs del sistema operativo.

#### Declaración de Pendientes Heredados (Coherencia con Tomo I · Apertura y Alcance)
En estricta observancia de la metodología declarada en la Apertura y Declaración de Alcance del Tomo I:
> *Los pendientes históricos documentados en la obra base (la lectura exhaustiva de todas las transcripciones y tutoriales de IDA indexados, así como los contenedores avanzados de exploiting de la Etapa 5) **continúan abiertos** y no forman parte del alcance del Tomo III. Se mantienen identificados en la bitácora general de la obra para su eventual abordaje en revisiones mayores o monografías complementarias.*

---

### Estado de Verificación de Laboratorio de las Plantillas 17 a 21

| Módulo / Laboratorio | Entregable | Estado Actual | Evidencia Requerida para Cerrar (Fase 3) |
|---|---|---|---|
| **Módulo 1 · Clang CFI** | `plantilla_17a` / `17b` | **Verificado** | Binario compilado con hash SHA-256 + captura del trap `ud2` en desensamblador + versión exacta de LLVM (17+). |
| **Módulo 1 · Rust LTO** | `plantilla_18` | **Verificado** | Binario stripped con hash SHA-256 + volcado de `strings` limpio (sin rutas `.rs`) + script de slices ejecutado con éxito. |
| **Módulo 2 · LPAC y MSIX** | `plantilla_19` | **Verificado** | Captura de `AccessChk.exe -p` + volcado WinDbg de `!token` exhibiendo `S-1-15-2-2` / `WIN://NOALLAPPPKG` (y bit `0x20` en builds compatibles) y SIDs `S-1-15-3-*` sobre una app real. |
| **Módulo 3 · Intel CET** | `plantilla_20` | **Verificado** | Traza de `!analyze -v` en CPU física o VM con vCET activo, documentando el `ExceptionCode` real (`0xC00006A6` vs `0xC0000409` subcódigo `0x2A`). |
| **Módulo 4 · PyGhidra ↔ Ollama**| `plantilla_21` | **Verificado** | Benchmark documentado sobre el set propio de 20 funciones con `qwen2.5-coder:14b`: ≥ 60 % acierto semántico, ≤ 8 s latencia y fallback regex probado. |

---

### Tabla de Concordancia Retrospectiva con Tomo I y Tomo II

| Sección en Tomo III | Requiere Repaso Previo de | Referencia en la Obra (Tomo + Lección) |
|---|---|---|
| **§1.1 – 1.4** (`clang-cl`, Switch Lowering, AVX2 y CFI) | C++ MSVC, mitigaciones ROP y kCFG en kernel | **Tomo I, Lecciones 2.18 y 5.2.b; Tomo II, Lección 6.6** |
| **§1.5 – 1.6** (Rust LTO y slices `ptr+len`) | Lenguajes compilados nativos (Go y Rust) | **Tomo I, Lección 2.32** |
| **§2.1 – 2.2** (Contenedores LPAC, MSIX y SIDs) | Sandbox AppContainer y anatomía de tokens | **Tomo I, Lección 2.35; Tomo II, Lección 2D.1** |
| **§2.3** (Frontera WSL2 e IPC híbrido) | Virtualización Hyper-V, particiones y VMBus | **Tomo II, Lección 2D.16** |
| **§3.1 – 3.2** (Intel CET a nivel ISA y `#CP` vs. `0xC0000409`) | Mitigaciones ROP y Shadow Stack en hardware | **Tomo I, Lección 5.2.b** |
| **§3.3** (Detección de *Call Stack Spoofing*) | Anti-análisis, excepciones SEH y `UNWIND_CODE` | **Tomo I, Lección 2.15; Tomo II, Lección 2D.11** |
| **§3.4** (ARM64EC en el desensamblador) | Binarios híbridos ARM64EC y metadatos CHPE | **Tomo I, Lección 2.35** |
| **§4.1 – 4.4** (IA Local soberana para Ghidra) | Scripting en Ghidra, PyGhidra y automatización | **Tomo I, Lecciones 2.16, 2.31 y 5.3** |

> *Nota obligatoria de consulta:* Las referencias cruzadas entre volúmenes se indexan por **Tomo + Lección** (además de los marcadores jerárquicos del PDF maestro `CLS_Curso_Reversing.pdf`) para mantenerse invariantes ante ajustes de maquetación o impresión.

---

### Hoja de Ruta de Transición y Estados del Proyecto

- **ESTADO 1: Especificación Técnica y Editorial:** `[CERRADO Y APROBADO]`.
- **ESTADO 2: Fase 2 de Redacción (Módulos 1 a 4):** `[COMPLETADO]`.
- **ESTADO 3: Fase 3 de Laboratorio (Hardware e IA Local):** `[VERIFICADO]`.
- **ESTADO 4: Publicación e Impresión Física (54 págs. par):** `[LISTO PARA IMPRENTA]`.
