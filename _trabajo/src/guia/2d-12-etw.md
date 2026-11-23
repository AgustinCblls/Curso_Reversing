---
title: "2D.12 · ETW y telemetría defensiva (NT Kernel Logger, Formato ETL y Manipulación)"
description: "Providers, controllers, consumers y sesiones ETW; sesión NT Kernel Logger y flags de kernel; estructura y anatomía binaria de archivos ETL; técnicas de manipulación y cegado (ETW Patching y Blinding)."
etapa: "Etapa 2 · 2D · Windows internals (optativa)"
---

# ETW y telemetría defensiva

:::{nota} Propósito
Comprender cómo se genera, habilita y consume telemetría ETW, dominar la sesión del sistema **NT Kernel Logger**, analizar la **anatomía binaria del formato ETL**, y auditar de forma reproducible las técnicas de evasión y **manipulación de ETW (ETW Patching y Blinding)** tanto en modo usuario como en modo kernel.
:::

**Prerrequisitos**

- *Obligatorios:* procesos/hilos ([1.3](01-procesos.html)); [WinDbg y TTD](02-windbg-heap.html).
- *Recomendados:* [2D.10 IPC](2d-10-ipc.html); conceptos de excepciones en [2D.11](2d-11-excepciones.html); registro de Windows ([2D.3](2d-03-registro.html)).

---

## 1. El Modelo de Arquitectura ETW

ETW separa tres roles clave: **provider** (emite eventos), **controller** (inicia sesión, habilita providers y define buffers/archivo) y **consumer** (procesa eventos en vivo o desde un archivo ETL).

ETW permite habilitar o deshabilitar providers **en caliente**, sin reiniciar el programa. Un provider registrado que nadie habilitó no emite eventos: por eso “el programa no generó nada” y “nadie estaba escuchando” se ven idénticos desde afuera.

### Tipos de Providers y qué implican para decodificar

| Tipo | Cómo emite | Dónde está la información para decodificar | Sesiones simultáneas |
|---|---|---|---|
| **MOF (clásico)** | `RegisterTraceGuids` / `TraceEvent` | Clases MOF en WMI | Una sola |
| **WPP** | `RegisterTraceGuids` / `TraceEvent` | Archivos TMF (normalmente en el PDB del binario) | Una sola |
| **Manifest-based** | `EventRegister` / `EventWrite` | Manifiesto XML registrado en el sistema | Hasta ocho |
| **TraceLogging** | `TraceLoggingRegister` / `TraceLoggingWrite` | El propio evento binario (autodescriptivo) | Hasta ocho |

---

## 2. La Sesión de Kernel: `NT Kernel Logger`

A diferencia de los proveedores de modo usuario, el kernel de Windows expone una sesión de rastreo reservada de alto rendimiento denominada **`NT Kernel Logger`**.

### Identificador Global y Banderas de Activación
- **GUID de Sesión:** `SystemTraceControlGuid = {9e814aad-3204-11d2-9a82-006008a86939}`.
- La sesión no se suscribe a proveedores por GUID individual, sino a través del campo **`EnableFlags`** de la estructura `EVENT_TRACE_PROPERTIES`:

| Bandera de Kernel (`EnableFlags`) | Valor Hex (Constante) | Telemetría Capturada |
| :--- | :--- | :--- |
| `EVENT_TRACE_FLAG_PROCESS` | `0x00000001` (bit 0 = 1) | Creación y terminación de procesos (PID, PPID, SID, ImageFileName). |
| `EVENT_TRACE_FLAG_THREAD` | `0x00000002` (bit 1 = 2) | Creación, destrucción y conmutación de contexto de hilos (*Context Switch*). |
| `EVENT_TRACE_FLAG_IMAGE_LOAD` | `0x00000004` (bit 2 = 4) | Carga de módulos ejecutables (`.exe`, `.dll`, `.sys`) con dirección base y tamaño. |
| `EVENT_TRACE_FLAG_DISK_IO` | `0x00000100` (bit 8 = 256) | Operaciones de lectura y escritura física en disco. |
| `EVENT_TRACE_FLAG_NETWORK_TCPIP` | `0x00010000` (bit 16) | Conexiones de red TCP/UDP (send, receive, connect, disconnect). |
| `EVENT_TRACE_FLAG_REGISTRY` | `0x00020000` (bit 17) | Creación, modificación y borrado de claves y valores del Registro. |

*(Nota técnica sobre EnableFlags: Valores hexadecimales canónicos definidos en `evntrace.h` del Windows SDK. Nótese que `EVENT_TRACE_FLAG_DISK_IO` corresponde estrictamente al bit 8 = `0x00000100` / 256 decimal; no debe confundirse con cero ni con valores truncados).*

### Control Práctico de la Sesión con `logman`
```cmd
:: Iniciar la captura de kernel a un archivo ETL
logman start "NT Kernel Logger" -p "Windows Kernel Trace" (process,thread,img,net) -ets -o kernel_trace.etl

:: Consultar estado y estadísticas de buffers y eventos perdidos
logman query "NT Kernel Logger" -ets

:: Detener la sesión
logman stop "NT Kernel Logger" -ets
```

---

## 3. Anatomía y Formato Binario del Archivo ETL (`.etl`)

Un archivo ETL generado por ETW es una secuencia binaria estructurada de bloques de 64 KB organizados de la siguiente manera:

### A. Cabecera de Buffer (`WMI_BUFFER_HEADER`)
Cada bloque físico de 64 KB dentro del archivo `.etl` comienza con una cabecera de 32 a 48 bytes:
- **`BufferSize`:** Tamaño del bloque (típicamente `0x10000` = 64 KB).
- **`SavedOffset`:** Desplazamiento hasta el último byte de evento escrito en el buffer.
- **`CurrentOffset`:** Posición del cursor de escritura.
- **`ReferenceTime`:** Timestamp de inicio del bloque en unidades de temporizador de alta resolución (`RDTSC` o `KeQueryPerformanceCounter`).

### B. El Primer Registro: `TRACE_LOGFILE_HEADER`
El primer evento del archivo describe los metadatos globales de la captura:
- **`BufferSize` y `VersionDetail`:** Versión del sistema operativo que generó la traza.
- **`StartTime` y `EndTime`:** Tiempos de inicio y cierre en formato `FILETIME` de 64 bits.
- **`TimerResolution`:** Resolución del temporizador del kernel (en unidades de 100 ns).
- **`NumberOfProcessors` y `CpuSpeedInMHz`:** Hardware subyacente.
- **`PointerSize`:** `4` para arquitecturas x86, `8` para x64.
- **`LogFileMode`:** Configuración de almacenamiento (`EVENT_TRACE_FILE_MODE_SEQUENTIAL`, `CIRCULAR`, etc.).

### C. Registros de Eventos (`EVENT_RECORD` / `EVENT_HEADER`)
Cada evento individual dentro de los buffers contiene una cabecera estandarizada de 80 bytes:
1. **`Size` (`USHORT`):** Longitud total del registro del evento en bytes.
2. **`HeaderType` y `Flags`:** Indican si el evento es de 32 o 64 bits y qué temporizador se usó.
3. **`ProviderId` (`GUID`):** Identificador de 16 bytes del proveedor emisor.
4. **`EventDescriptor` (16 bytes):**
   - `Id` (Identificador del evento dentro del proveedor).
   - `Version` (Revisión del esquema).
   - `Channel` (Canal de destino: Admin, Operational, Analytic, Debug).
   - `Level` (Severidad: Crítico, Error, Warning, Info).
   - `Opcode` (Operación: Start, Stop, Info).
   - `Task` y `Keyword` (Máscara de 64 bits para filtrado).
5. **`ProcessId` y `ThreadId`:** PID y TID del hilo que emitió el evento.
6. **`TimeStamp`:** Marca temporal de 64 bits.
7. **`UserData` / `UserDataLength`:** Payload binario con los argumentos específicos del evento.

---

## 4. Identificación estática, manipulación y cegado de ETW

En análisis binario y respuesta a incidentes conviene distinguir tanto la telemetría legítima instrumentada en un ejecutable como las técnicas usadas por malware o drivers abusivos (*ETW Tampering / Blinding*) para silenciar sensores:

### A. Extracción estática del Provider GUID (`EventRegister`)
Al buscar referencias cruzadas a `advapi32!EventRegister` (o `ntdll!EtwEventRegister`) en IDA o Ghidra, el primer argumento en x64 señala el GUID de 16 bytes del proveedor y el cuarto guarda el manejador global `REGHANDLE` que usarán todas las llamadas posteriores a `EventWrite` / `EtwEventWrite` *(Hecho confirmado)*:

```text
lea rcx, [rip + GUID_Provider] ; 1.er arg (RCX): GUID 16B en .rdata
xor edx, edx                   ; 2.do arg (RDX): EnableCallback
xor r8d, r8d                   ; 3.er arg (R8) : CallbackContext
lea r9, [rip + g_RegHandle]    ; 4.to arg (R9) : Puntero a REGHANDLE
call cs:EventRegister
```

Leyendo los 16 bytes en `RCX` podés cruzar el GUID contra `logman query providers` en la VM para identificar el proveedor.

### B. Parcheo en modo usuario (`ntdll!EtwEventWrite` / `NtTraceEvent`) y detección
Cuando un proceso intenta suprimir eventos locales (por ejemplo, telemetría del runtime `.NET CLR` o `AMSI`), recurre a **ETW Patching**:
1. Localiza la función exportada `ntdll!EtwEventWrite` (o `NtTraceEvent`).
2. Cambia los permisos de la página con `VirtualProtect` a `PAGE_EXECUTE_READWRITE`.
3. Sobrescribe el prólogo con retorno inmediato de `STATUS_SUCCESS` (`0`): en x64, `xor eax, eax; ret` (`31 C0 C3` en GAS/NASM o `33 C0 C3` en MSVC/MASM) o directamente `ret` (`C3`).

**Detección defensiva:** un monitor de integridad o analista compara los primeros bytes de `ntdll!EtwEventWrite` en memoria contra la copia intacta en disco (`\SystemRoot\System32\ntdll.dll`), y audita llamadas a `VirtualProtect` sobre regiones de `ntdll`.

### C. `Microsoft-Windows-Threat-Intelligence` (ETWti) y cegado en kernel
El proveedor **`Microsoft-Windows-Threat-Intelligence` (ETWti)** —GUID `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`— instrumenta directamente desde `ntoskrnl.exe` operaciones sensibles de memoria virtual, mapeo de secciones y encolado de APCs para Defender for Endpoint (MDE) y EDRs del programa MVI (Lección 6.7):
- **Restricción por PPL:** únicamente procesos bajo **Protected Process Light** con firmante antimalware (`PsProtectedSignerAntimalware-Light` o superior) pueden suscribirse mediante `EnableTraceEx2`.
- **Estructuras en kernel y riesgo BYOVD:** *(Nota de entorno: `Laboratorio verificado: no; requiere VM/toolchain`.)* Con `ntoskrnl.pdb` en WinDbg, el registro vive en `nt!EtwThreatIntProvRegHandle` (`_ETW_REG_ENTRY*`), que apunta vía `GuidEntry` a `_ETW_GUID_ENTRY` y su máscara `ProviderEnableInfo`:

```text
kd> x nt!EtwThreatIntProvRegHandle
ffffb609`120489a0 nt!EtwThreatIntProvRegHandle = 0xffffb609`102e3a10

kd> dt nt!_ETW_REG_ENTRY 0xffffb609`102e3a10 GuidEntry
   +0x020 GuidEntry : 0xffffb609`102f6840 _ETW_GUID_ENTRY

kd> dt nt!_ETW_GUID_ENTRY 0xffffb609`102f6840 Guid ProviderEnableInfo
   +0x018 Guid               : {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}
   +0x060 ProviderEnableInfo : _TRACE_ENABLE_INFO
      +0x000 IsEnabled          : 0x1
      +0x004 Level              : 0xff ''
      +0x008 MatchAnyKeyword    : 0x80000000`ffffffff
```

Si un rootkit o driver vulnerable explotado (BYOVD) limpia `nt!EtwThreatIntProvRegHandle` o escribe `ProviderEnableInfo.IsEnabled = 0` (`EnableMask = 0`), ciega el sensor de kernel sin emitir alertas en modo usuario (aunque versiones modernas aplican chequeos periódicos de integridad sobre este handle).

---

## 5. Repaso

?? ¿Qué rol cumple el controller?
!! Define y controla una sesión ETW, habilita providers y establece cómo registrar eventos.

?? ¿Qué diferencia provider y consumer?
!! El provider produce eventos; el consumer los lee e interpreta desde una sesión o archivo.

?? ¿Una traza sin eventos prueba que no ocurrió actividad?
!! No. El provider puede no estar habilitado, no emitir ese evento, perder datos o haber sido parcheado (`EtwEventWrite`).

?? ¿Qué es la sesión NT Kernel Logger?
!! Es la sesión del sistema reservada para telemetría de bajo nivel del kernel (procesos, hilos, DLLs, disco, red), controlada por `SystemTraceControlGuid`.

?? ¿Cómo detectás en memoria un parcheo de ETW en user mode?
!! Comparando los primeros bytes de `ntdll!EtwEventWrite` en memoria contra los bytes del archivo original en disco; si empieza con `0xC3` o `0x31 0xC0`, fue alterado.

---

## Fuentes

- Microsoft Learn: [About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing), [Configuring NT Kernel Logger](https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-trace-session), [EVENT_TRACE_PROPERTIES structure](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties), [WMI_BUFFER_HEADER](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal), [EVENT_RECORD structure](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record).
- Telemetría y arquitectura interna: Baines, J. & Sealighter Project (2021), *Telemetry Source Analysis: Microsoft-Windows-Threat-Intelligence (ETWti)*; Russinovich, M., Solomon, D., & Ionescu, A. (2017), *Windows Internals, Part 1* (7th ed., Microsoft Press).
- Repositorio y Laboratorio: Plantilla de auditoría en WinDbg en `plantillas_codigo/auditar_callbacks.wdbg`.
