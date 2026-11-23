# Módulo 3 · ISA de Hardware para Reversing: Intel CET, Stack Spoofing y ARM64EC
*(Tomo III · Prerrequisitos: Tomo I, Lección 5.2.b y Lección 2.35; Tomo II, Lección 2D.11)*

---

## 3.1 Intel CET (Control-flow Enforcement Technology) a Nivel de Opcode

En el Tomo I (Lección 5.2.b) se abordaron las defensas clásicas contra la Programación Orientada a Retornos (ROP) basadas en software: los canarios de pila (*GS Cookies* / `__security_check_cookie`) y SafeSEH. Sin embargo, estas mitigaciones no impiden la manipulación de direcciones de retorno cuando un atacante cuenta con primitivas de lectura/escritura arbitraria de memoria.

La respuesta de la microarquitectura moderna (Intel Core de 11.ª generación en adelante y AMD Zen 3+) es **Intel CET**, una tecnología de blindaje respaldada por silicio que introduce una segunda pila aislada: la **Pila Sombra (Shadow Stack)**.

```
         MECÁNICA ATÓMICA DE INTEL CET SHADOW STACK

          Flujo de Ejecución (CALL Target)
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
   [ Pila Convencional ]     [ Pila Sombra (Hardware) ]
   RSP -> [ Return Addr ]    SSP -> [ Return Addr ]
   (Escribible por SW)       (Solo modificable por CPU)
            │                         │
            └────────────┬────────────┘
                         │
               Retorno de Función (RET)
                         │
                 ¿ [RSP] == [SSP] ?
            ├─ (SÍ: Coinciden) ──> Ejecución continúa
            └─ (NO: Manipulado) -> EXCEPCIÓN #CP (0xC00006A6)
```

### Operación en el Conjunto de Instrucciones (ISA)
La pila sombra reside en memoria física mapeada con permisos especiales de procesador (accesible solo en lectura para el código de usuario, modificable exclusivamente por la unidad de ejecución de la CPU):
1. **Instrucción `CALL`:** La CPU decrementa `RSP` y guarda la dirección de retorno en `[RSP]`. Simultáneamente, decrementa el **Puntero de Pila Sombra (`SSP`)** y guarda una copia idéntica en `[SSP]`.
2. **Instrucción `RET`:** La CPU desapila la dirección de `[RSP]` y la de `[SSP]`. Compara ambos valores de manera atómica antes de actualizar `RIP`. Si difieren (indicativo de que un desbordamiento o exploit sobreescribió la pila ordinaria), la CPU aborta la instrucción e interrumpe la ejecución mediante una falla de hardware.

### Nuevos Opcodes de CET en el Desensamblador
Al analizar binarios compilados con soporte CET en Windows 11 (`/CETCOMPAT` en el enlazador de MSVC), el reverser se encontrará con instrucciones de máquina dedicadas:

#### A. `RDSSP reg64` (*Read Shadow Stack Pointer*)
Lee el valor actual del registro de control `SSP` y lo deposita en un registro de propósito general (ej. `RDSSPQ RAX`). Se utiliza en rutinas de inspección de integridad y telemetría de depuración.
```assembly
; Opcode: F3 48 0F 1E C8 (F3 + prefijo REX.W 48 + 0F 1E /1)
rdsspq  rax                     ; RAX = Dirección virtual actual de la Pila Sombra
```

#### B. `INCSSP reg64` (*Increment Shadow Stack Pointer*)
Avanza el puntero `SSP` un número determinado de marcos (en múltiplos de 8 bytes). 
* **Por qué existe:** Cuando el sistema operativo desenrolla la pila por una excepción estructurada (SEH) o una llamada a `longjmp`, la pila convencional `RSP` es liberada de golpe saltando varios marcos de llamada. Para mantener la coherencia, el gestor de excepciones de Windows (`ntdll!RtlUnwindEx`) debe avanzar la pila sombra mediante `INCSSP` para descartar los punteros de retorno correspondientes a los marcos abandonados.

```assembly
; Opcode: F3 49 0F AE EA (F3 + REX.WB 49 + 0F AE /5)
incsspq r10                     ; R10 = número de frames de 8 bytes a saltar en SSP
```

#### C. `SAVEPREVSSP` y `RSTORSSP` (*Save and Restore Shadow Stack*)
Utilizadas durante la conmutación de hilos o fibras (*User-Mode Scheduling / Fibers*):
* `SAVEPREVSSP`: Guarda el puntero previo en el registro de sombra antes de un cambio de contexto.
* `RSTORSSP`: Restaura la pila sombra del hilo entrante verificando una marca de sincronización (*shadow stack restore token*).

```assembly
; Opcodes dedicados para cambio de contexto seguro
saveprevssp                     ; Opcode: F3 0F 01 EA (sin operandos de registro)
rstorssp qword ptr [rcx]        ; Opcode: F3 0F 01 29 (RCX = token de restauración)
```

---

## 3.2 El Desglose Quirúrgico de Excepciones: `#CP` vs. `FAST_FAIL_CONTROL_PROTECTION_USER`

Uno de los errores más frecuentes en la literatura de seguridad consiste en confundir la interrupción pura de hardware de la CPU con la rutina de terminación rápida por software de Windows.

### 1. La Excepción de Hardware Pura de la CPU (`#CP` - Vector 21)
* Cuando la instrucción `RET` detecta `[RSP] != [SSP]`, la CPU genera la interrupción de hardware número 21 (**`#CP` — Control Protection Exception**).
* El despachador de trampas del kernel de Windows (`nt!KiControlProtectionFault`) captura la interrupción del procesador y la mapea a la excepción de NTSTATUS formal:
  **`STATUS_CONTROL_PROTECTION_EXCEPTION = 0xC00006A6`**
* En un depurador conectado al proceso, si la excepción es despachada hacia el manejador de excepciones del proceso, se observará:
  ```text
  (1a4c.1b20): Control protection violation - code c00006a6 (first chance)
  First chance exceptions are reported before any exception handling.
  This exception may be expected and handled.
  ntdll!KiUserExceptionDispatch:
  00007ff8`9a123b40 4883ec50        sub     rsp,50h
  ```

### 2. El Mecanismo de Fast-Fail por Software (`int 0x29`)
* Si el compilador (CRT de MSVC) o el cargador de Windows determinan que la anomalía representa una corrupción crítica que no debe permitir la ejecución de ningún bloque `__except` (para evitar que el atacante secuestre el propio manejador de excepciones), el runtime invoca directamente la instrucción:
  ```assembly
  mov     ecx, 2Ah                ; 0x2A = FAST_FAIL_CONTROL_PROTECTION_USER (42 decimal)
  int     29h                     ; Fast-Fail directo al kernel (nt!KiRaiseSecurityCheckFailure)
  ```
* En WinDbg, una terminación por `int 0x29` se reporta invariablemente como:
  **`STATUS_STACK_BUFFER_OVERRUN = 0xC0000409`**
  con el subcódigo `0x2A` (*Subcode: FAST_FAIL_CONTROL_PROTECTION_USER*) registrado en el parámetro de fallo del volcado.

**Resumen Operativo para el Analista:**
* Si en el volcado de memoria observa **`0xC00006A6`**, la violación fue capturada directamente por la trampa de hardware `#CP` de la CPU.
* Si observa **`0xC0000409` con subcódigo `0x2A`**, el código de usuario o el subsistema de mitigaciones despachó una terminación preventiva rápida antes de permitir que la CPU o el unwinder procesaran el fallo.

---

## 3.3 Detección Práctica y Análisis Forense de *Call Stack Spoofing*

En la Lección 2.15 del Tomo I se analizaron técnicas de evasión de telemetría de antivirus y EDRs. Uno de los métodos ofensivos más sofisticados es el **Falseo de la Pila de Llamadas (*Call Stack Spoofing*)**:
* Cuando un implante o malware desea invocar una API sospechosa (como `VirtualAlloc` con permisos `PAGE_EXECUTE_READWRITE` o `WriteProcessMemory`), sabe que los sensores EDR inspeccionan la pila de llamadas (*call stack*) para verificar desde dónde provino la invocación.
* Para evadir la detección, el malware sobreescribe sintéticamente la dirección de retorno en `[RSP]` para que apunte al interior de una DLL legítima del sistema (como `kernelbase.dll` o `ntdll.dll`), simulando ser una función inofensiva de Windows.

### Cómo Audita la Pila un Sensor Defensivo Moderno
Un motor de detección robusto o un analista en WinDbg valida la autenticidad del call stack mediante tres pruebas concurrentes:

```
             TRIPLE VALIDACIÓN DE INTEGRIDAD DE STACK

  [ Dirección de Retorno en Stack: ReturnAddress ]
        │
        ├─> 1. Verificación de Código Previo:
        │      ¿La instrucción previa es CALL (E8 / FF /2)?
        ├─> 2. Desenredo Coherente (UNWIND_INFO):
        │      ¿RtlVirtualUnwind llega hasta RtlUserThreadStart?
        └─> 3. Coherencia Hardware CET:
               ¿Coincide exactamente [RSP] con [SSP]?
```

#### 1. Verificación de Opcode Invocador (`CALL` vs `JMP`)
Cuando una función retorna, el valor previo a `ReturnAddress` en memoria ejecutable DEBE ser una instrucción `CALL`. Si un atacante forjó un frame apuntando a una instrucción cualquiera después de un `JMP` o una instrucción no relacionada, el analizador detecta la anomalía:
```c
// Lógica defensiva para validar el caller
uint8_t* caller_site = (uint8_t*)return_address;
if (caller_site[-5] == 0xE8) {
    // Invocación válida mediante CALL relativo (5 bytes)
} else if (caller_site[-2] == 0xFF || caller_site[-3] == 0xFF) {
    // Invocación válida mediante CALL indirecto (FF /2)
} else {
    // ¡ALERTA! El call site previo NO es una llamada -> Stack Spoofing Detectado
}
```

#### 2. Desenredo SEH con `UNWIND_INFO`
Como se estudió en el Tomo II (Lección 2D.11), cada función en x64 posee una entrada en la tabla `.pdata`. El sensor ejecuta `RtlVirtualUnwind` paso a paso: si en algún punto el tamaño del marco de pila no coincide con los códigos de desenredo (`UWOP_ALLOC_SMALL`, `UWOP_PUSH_NONVOL`), el stack se clasifica como sintético.

#### 3. El Fin del Call Stack Spoofing con Intel CET
Bajo un entorno con CET activo, **el Call Stack Spoofing tradicional es matemáticamente inviable**:
* El atacante puede modificar `[RSP]` a voluntad en modo usuario.
* Pero **no puede modificar `[SSP]`**, porque la pila sombra es de solo lectura y solo la CPU puede escribir en ella mediante `CALL`.
* Al retornar de la API inyectada, la discrepancia entre el `[RSP]` falso y el `[SSP]` genuino dispara instantáneamente la excepción `#CP` (`0xC00006A6`), anulando la evasión.

---

## 3.4 ARM64EC en el Desensamblador Híbrido

En el Tomo I (Lección 2.35) se introdujo el concepto de binarios **ARM64EC** (*Emulation Compatible*), la tecnología de Microsoft para permitir que código x64 nativo y código ARM64 convivan dentro del mismo espacio de proceso en dispositivos Windows 11 con procesadores Qualcomm Snapdragon X Elite / ARM64.

### La Anatomía de los Trampolines `$$h` (*Entry Thunks*)
Cuando una función ARM64EC es invocada desde un módulo x64, los 4 primeros argumentos enteros/puntero ya mapean **1:1** según la ABI oficial de Microsoft ARM64EC (visto en **Tomo I, Lección 2.35**):
* `RCX → X0`, `RDX → X1`, `R8 → X2`, `R9 → X3` (y registros flotantes/SIMD hacia `V0–V3`).

El compilador emite un **Entry Thunk** con el sufijo `$$h` para ajustar la frontera ABI: preservar el enlace/marco de pila, alinear argumentos adicionales en stack o registros SIMD y adaptar el retorno hacia la rutina ARM64 nativa (`#FuncionSegura`):

```assembly
; ==============================================================================
; Desensamblado ilustrativo de Entry Thunk ARM64EC (#FuncionSegura$$h)
; Nota: RCX->X0, RDX->X1, R8->X2, R9->X3 ya llegan mapeados 1:1 por la ABI
; ==============================================================================
#FuncionSegura$$h:
    stp     fp, lr, [sp, #-16]!     ; Preservar frame pointer y link register (x64 retaddr)
    mov     fp, sp
    ; ... ajustar argumentos extra en stack / registros SIMD si aplica ...
    bl      #FuncionSegura          ; Invocar implementación ARM64 nativa (X0..X3 intactos)
    ldp     fp, lr, [sp], #16       ; Restaurar marco (el retorno queda en X8/X0 según ABI)
    ret
```

### El Directorio de Metadatos CHPE en el PE Load Config
En el archivo binario PE, un ejecutable ARM64EC posee un encabezado `IMAGE_FILE_MACHINE_ARM64` (0xAA64), pero su tabla de configuración de carga (`IMAGE_LOAD_CONFIG_DIRECTORY64`) incluye punteros hacia estructuras CHPE:
* `CHPEMetadataPointer`: Apunta a la tabla `IMAGE_ARM64EC_METADATA`.
* `ExtraRFETable`: Tabla extendida de excepciones para código emulado.
* `xtajit64.dll`: El motor JIT en modo usuario que intercepta las llamadas indirectas y conmuta entre el emulador x64 y la ejecución nativa en silicio ARM64.

---

## 3.5 Resumen de Prácticas del Módulo 3

Para afianzar los conceptos desarrollados en este módulo:
* [`plantillas_codigo/plantilla_20_cet_shadow_stack.c`](plantillas_codigo/plantilla_20_cet_shadow_stack.c): Binario en C para lectura de `SSP` con `_rdsspq()` y verificación de hardware CET en modo usuario.
* Análisis en depurador de la trampa de hardware `#CP` (`0xC00006A6`) frente al fast-fail `int 0x29` (`0xC0000409`).
