---
title: "2D.15 · Reversing de Arranque Temprano, UEFI y Cadena de Carga (bootmgfw, winload, LOADER_PARAMETER_BLOCK)"
description: "Formato PE32+ de aplicaciones EFI, layout binario de EFI_SYSTEM_TABLE, cadena de inicialización de arranque (bootmgfw.efi, winload.efi, hvloader.efi), estructura LOADER_PARAMETER_BLOCK y análisis de bootkits en Ghidra/IDA."
etapa: "Etapa 2 · 2D · Windows internals (optativa)"
---

# Reversing de Arranque Temprano, UEFI y Cadena de Carga

:::{nota} Propósito y Alcance
El análisis del sistema operativo no comienza cuando el kernel ya está en ejecución. Para comprender las amenazas más persistentes (Bootkits UEFI, técnicas de desactivación temprana de DSE, y el despliegue del hipervisor VBS antes de `ntoskrnl.exe`), el analista de ingeniería inversa debe dominar el proceso de arranque temprano de Windows en plataformas de 64 bits con firmware **UEFI**. Esta lección disecciona la cadena de cargadores EFI, el layout de estructuras del firmware, el formato de los módulos DXE y la estructura de transición fundamental: el bloque **`LOADER_PARAMETER_BLOCK`**.
:::

---

## 1. El Formato PE32+ de las Aplicaciones EFI

Los archivos ejecutables del cargador de arranque de Windows (como `bootmgfw.efi`, `winload.efi` y `hvloader.efi`) no son formatos binarios propietarios exóticos: son archivos estándar **PE32+ (PE de 64 bits)** con características específicas en sus cabeceras:

1. **`Subsystem` en OptionalHeader:**
   - `IMAGE_SUBSYSTEM_EFI_APPLICATION` (`10` / `0x000A`): Aplicaciones que se ejecutan directamente bajo el entorno UEFI antes de que el sistema operativo tome el control.
   - `IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER` (`11` / `0x000B`): Controladores DXE que extienden los servicios de arranque de la placa madre.
2. **Punto de Entrada EFI:**
   La función de inicio de un ejecutable EFI recibe siempre dos parámetros estandarizados en la convención x64 de Microsoft:
   ```c
   EFI_STATUS EFIAPI EfiMain(
       IN EFI_HANDLE ImageHandle,       // RCX: Handle del binario cargado en memoria
       IN EFI_SYSTEM_TABLE *SystemTable // RDX: Puntero a la tabla global de servicios UEFI
   );
   ```

### Layout Binario de `EFI_SYSTEM_TABLE` en x64
En un ejecutable UEFI desensamblado, toda interacción con memoria, consola y protocolos se realiza a través de la tabla `SystemTable` pasada en `RDX`. En arquitecturas de 64 bits, su disposición en memoria es fija:

| Offset (x64) | Campo | Tipo | Propósito |
| :--- | :--- | :--- | :--- |
| **`+0x00`** | `Hdr` | `EFI_TABLE_HEADER` | Cabecera estándar de 24 bytes (Firma mágica `0x5453595320494249` = `"IBI SYST"`, revisión, tamaño y CRC32). |
| **`+0x18`** | `FirmwareVendor` | `CHAR16*` | Puntero a cadena Unicode UTF-16 con el nombre del fabricante del BIOS/UEFI. |
| **`+0x20`** | `FirmwareRevision` | `UINT32` | Versión interna del firmware. |
| **`+0x24`** | `_Padding` | `UINT32` | Relleno de alineación a 8 bytes en arquitecturas de 64 bits. |
| **`+0x28`** | `ConsoleInHandle` | `EFI_HANDLE` | Handle del dispositivo de entrada estándar (teclado). |
| **`+0x30`** | `ConIn` | `EFI_SIMPLE_TEXT_INPUT_PROTOCOL*` | Puntero al protocolo de lectura de caracteres del teclado. |
| **`+0x38`** | `ConsoleOutHandle` | `EFI_HANDLE` | Handle de la salida de texto (pantalla). |
| **`+0x40`** | `ConOut` | `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*` | Puntero al protocolo de impresión de texto en pantalla. |
| **`+0x48`** | `StandardErrorHandle`| `EFI_HANDLE` | Handle del dispositivo de error. |
| **`+0x50`** | `StdErr` | `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*` | Puntero a la salida de errores en pantalla. |
| **`+0x58`** | `RuntimeServices` | `EFI_RUNTIME_SERVICES*` | Puntero a la tabla de servicios en tiempo de ejecución (`gRT`), que persisten tras arrancar el SO (variables NVRAM). |
| **`+0x60`** | `BootServices` | `EFI_BOOT_SERVICES*` | Puntero a la tabla de servicios de arranque (`gBS`), activa solo hasta que se invoca `ExitBootServices`. |

### El porqué del Padding de 4 bytes (`+0x24`) y Desensamblado en x64
En la especificación UEFI y en la ABI x64 de Microsoft, los punteros de 64 bits (`CHAR16*`, `EFI_HANDLE`, punteros a tablas de servicios) exigen **alineación natural obligatoria a 8 bytes** (`offset % 8 == 0`):
1. `Hdr` mide 24 bytes (`0x18`), ocupando `+0x00` a `+0x18`.
2. `FirmwareVendor` es un puntero (8 bytes), ocupando `+0x18` a `+0x20`.
3. `FirmwareRevision` es un entero de 32 bits `UINT32` (4 bytes), ocupando `+0x20` a `+0x24`.
4. El siguiente miembro declarado es `EFI_HANDLE ConsoleInHandle` (un puntero de 8 bytes). Si el compilador lo ubicara inmediatamente en `+0x24`, rompería la alineación de 8 bytes (ya que `0x24` no es múltiplo de 8).
5. Por lo tanto, el compilador C inserta automáticamente **4 bytes de relleno inactivo** (`_Padding` en `+0x24` a `+0x28`).
6. A partir de `ConsoleInHandle` en `+0x28`, se suceden 7 punteros de 64 bits consecutivos ($7 \times 8 = 56 = \text{0x38}$ bytes): `0x28 + 0x38 = 0x60`.
7. Gracias a este padding riguroso, el puntero crítico **`BootServices`** se ubica indefectiblemente en el offset **`+0x60`**.

#### Desensamblado en x64: Cómo el Firmware o Bootkit Recupera `BootServices`
```asm
; =========================================================================
; Prólogo estándar de una aplicación EFI (bootmgfw.efi / winload.efi / malware UEFI)
; Convención Microsoft x64: RCX = ImageHandle, RDX = SystemTable (EFI_SYSTEM_TABLE*)
; =========================================================================
EfiMain PROC
    mov     qword ptr [rsp + 10h], rdx  ; Salvar SystemTable en shadow space
    mov     qword ptr [rsp + 08h], rcx  ; Salvar ImageHandle
    sub     rsp, 28h

    ; Desreferenciar BootServices desde SystemTable (+0x60)
    mov     rax, qword ptr [rdx + 60h]  ; RAX = SystemTable->BootServices (¡offset exacto +0x60!)
    mov     qword ptr [gBS], rax        ; Almacenar en la variable global gBS

    ; Demostración de invocación de protocolo vía BootServices:
    ; LocateProtocol está en el offset +0x140 dentro de EFI_BOOT_SERVICES
    mov     rax, qword ptr [gBS]
    lea     r8, [pProtocol]             ; Argumento 3: Puntero de salida
    xor     edx, edx                    ; Argumento 2: Registration = NULL
    lea     rcx, [ProtocolGuid]         ; Argumento 1: Protocol GUID
    call    qword ptr [rax + 140h]      ; Invocar gBS->LocateProtocol()

    add     rsp, 28h
    ret
EfiMain ENDP
```

---

## 2. La Cadena de Carga de Windows en Sistemas x64 / UEFI

El proceso de arranque moderno desde el encendido de la máquina hasta la primera instrucción del kernel sigue una secuencia estricta de componentes encadenados y firmados bajo **Secure Boot**:

```text
[ Encendido / Reset ]
         │
         ▼
[ Firmware UEFI (SEC -> PEI -> DXE -> BDS) ]
         │ (Carga desde partición ESP FAT32: \EFI\Microsoft\Boot\bootmgfw.efi)
         ▼
[ Windows Boot Manager (bootmgfw.efi) ]
         │ 1. Parsea la base de datos BCD (\EFI\Microsoft\Boot\BCD)
         │ 2. Si BitLocker está activo: desbloquea la clave TPM mediante llamadas EFI
         │ 3. Carga y verifica la firma digital del cargador del SO
         ▼
[ Windows OS Loader (winload.efi) ]
         │ 1. Configura el mapa preliminar de tablas de páginas de 4 niveles (PML4)
         │ 2. Carga la colmena de registro SYSTEM (HKLM\SYSTEM) desde el disco
         │ 3. Carga ntoskrnl.exe, hal.dll y drivers con StartType = 0 (SERVICE_BOOT_START)
         │ 4. Si VBS está habilitado: invoca a hvloader.efi para iniciar Hyper-V
         │ 5. Llama a EFI_BOOT_SERVICES->ExitBootServices() (Termina el firmware)
         ▼
[ Kernel EntryPoint: ntoskrnl.exe!KiSystemStartup(LOADER_PARAMETER_BLOCK* pLpb) ]
```

---

## 3. La Estructura de Transición: `LOADER_PARAMETER_BLOCK`

Cuando `winload.efi` invoca la función de arranque del kernel (`nt!KiSystemStartup`), el hardware ya no tiene acceso a los servicios de UEFI (se ha llamado a `ExitBootServices`). La única vía por la cual el cargador transfiere información vital al kernel es mediante un puntero único pasado en el registro **`RCX`**: la estructura **`LOADER_PARAMETER_BLOCK`**.

### Offsets Críticos de `LOADER_PARAMETER_BLOCK` en x64 (Win10 22H2 / Win11 23H2–24H2):
Los primeros 16 bytes (`+0x000..+0x00F`) contienen `OsMajorVersion`, `OsMinorVersion`, `Size` y `OsLoaderSecurityVersion` (4 `ULONG`s). A partir de `+0x010` se ubican las cabezas de lista:
- **`+0x010` `LoadOrderListHead` (`_LIST_ENTRY`):** Lista doblemente enlazada de `_KLDR_DATA_TABLE_ENTRY` que enumera los módulos y drivers cargados en memoria por `winload.efi` (`ntoskrnl.exe`, `hal.dll`, `kd.dll` y drivers de arranque).
- **`+0x020` `MemoryDescriptorListHead` (`_LIST_ENTRY`):** Lista de descriptores `_MEMORY_ALLOCATION_DESCRIPTOR` con el mapa de memoria física clasificado por tipos.
- **`+0x030` `BootDriverListHead` (`_LIST_ENTRY`):** Lista de nodos `_BOOT_DRIVER_LIST_ENTRY` a inicializar en el arranque (seguida en `+0x040` por `EarlyLaunchListHead`, `+0x050` por `CoreDriverListHead`, `+0x060` por `CoreExtensionsDriverListHead` y `+0x070` por `TpmCoreDriverListHead`).
- **`+0x0F0` `Extension` (`Ptr64 _LOADER_PARAMETER_EXTENSION`):** Puntero a la extensión del bloque de arranque (en Windows 7 residía en `+0x098`; en Windows 10 22H2 y Windows 11 23H2/24H2 reside en `+0x0F0`). Contiene la configuración de **VBS/HVCI**, estado de **Hyper-V** y metadatos de integridad de código (*Code Integrity*).

### Inspección en WinDbg durante el Arranque Temprano
Si estás depurando una máquina virtual con WinDbg y configuras un breakpoint inicial (`sxe ibp` o `break` antes del kernel):
```text
$$ Inspeccionar el bloque de parámetros pasado a KiSystemStartup en RCX
dt nt!_LOADER_PARAMETER_BLOCK @rcx
$$ Volcar la lista de módulos cargados en el arranque
!list -t nt!_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks -x "dps @$extret+0x30 L2" (poi(@rcx+0x10))
```

---

## 4. Metodología de Análisis de Módulos EFI y Bootkits en IDA / Ghidra

Los bootkits modernos (como BlackLotus o Bootkm) buscan infectar la cadena de arranque antes de que `ntoskrnl.exe` active los mecanismos de protección de PatchGuard o las políticas de EDR.

### Pasos de Reversing para un Binario `.efi`:
1. **Carga en el Desensamblador:** Seleccionar el formato PE. En Ghidra o IDA Pro, utilizar los tipos de datos de UEFI (importando los headers de EDK2 o utilizando el plugin *EFISeek* / *Ghidra-EFI*).
2. **Localización de `SystemTable`:**
   En el prólogo de `EfiMain`, identificar la instrucción que salva el registro `RDX` en una variable global. Ese puntero es `gST` (`EFI_SYSTEM_TABLE`). En el offset **`+0x60`** de `gST` reside el puntero a `gBS` (`EFI_BOOT_SERVICES`).
3. **Identificación de Protocolos Hijackeados:**
   Los bootkits suelen instalar ganchos sobre funciones críticas de `EFI_BOOT_SERVICES` antes de que se cargue `winload.efi`:
   - Ganchos sobre **`LocateProtocol`** o **`OpenProtocol`**: interceptan la carga de protocolos para devolver punteros a rutinas modificadas.
   - Ganchos sobre **`ExitBootServices`**: capturan el momento exacto en que `winload.efi` va a transferir el control al kernel. En este punto, el bootkit parchea en memoria viva las rutinas de validación de firmas de `winload.efi` o inyecta código en `ntoskrnl!KiSystemStartup` para deshabilitar DSE antes de que el kernel arranque.
4. **Verificación Defensiva:** En sistemas corporativos, la integridad de esta cadena se audita mediante **Measured Boot** (el chip TPM registra los hashes SHA-256 de cada componente de arranque en los registros PCR 0 a 7, permitiendo a la red verificar remotamente que ningún binario EFI fue alterado).

## Práctica

1. En una copia en solo lectura de un binario EFI legítimo (por ejemplo, una aplicación EFI propia compilada con EDK2 o `bootmgfw.efi` tomado de una ISO/VM limpia), abrilo en IDA o Ghidra seleccionando subsistema EFI/PE x64 y cargando las cabeceras/tipos UEFI.
2. Identificá el punto de entrada `EfiMain(ImageHandle, SystemTable)`, localizá dónde se guarda `RDX` en la variable global `gST` y seguí la desreferencia en offset **`+0x60`** hacia `EFI_BOOT_SERVICES` (`gBS`), anotando llamadas por offset como `LocateProtocol` (`+0x140`).
3. En WinDbg conectado desde el arranque temprano de la VM (`sxe ibp`), inspeccioná `dt nt!_LOADER_PARAMETER_BLOCK @rcx` y comprobá los offsets de `LoadOrderListHead` y `Extension` en el build concreto de Windows.

## Entregable

Diagrama de la cadena de confianza (`SEC/PEI/DXE/BDS -> bootmgfw.efi -> winload.efi -> KiSystemStartup`), captura de análisis estático identificando `SystemTable` y `BootServices (+0x60)` en una app EFI benigna, y tabla de campos de `_LOADER_PARAMETER_BLOCK` verificados con el PDB del sistema.

## Repaso

?? ¿Qué recibe `EfiMain` en los registros `RCX` y `RDX` según la ABI UEFI x64 y qué offset apunta a `EFI_BOOT_SERVICES`?
!! `RCX` recibe `EFI_HANDLE ImageHandle` y `RDX` recibe el puntero a `EFI_SYSTEM_TABLE` (`gST`). Dentro de `EFI_SYSTEM_TABLE` en x64, el campo `BootServices` (`gBS`) reside exactamente en el desplazamiento `+0x60`.

?? ¿Qué ocurre en la transición marcada por `ExitBootServices()` y cómo obtiene el kernel el inventario de memoria y módulos cargados?
!! Al invocar `gBS->ExitBootServices()`, `winload.efi` toma control exclusivo de la memoria física y los servicios de tiempo de arranque UEFI dejan de estar disponibles. Por eso el cargador pasa al punto de entrada `nt!KiSystemStartup` el puntero a `LOADER_PARAMETER_BLOCK` en `RCX`, con las listas de módulos cargados, mapa de memoria y configuración VBS/CI.

?? ¿Por qué los desplazamientos internos de `LOADER_PARAMETER_BLOCK` como `Extension` cambian entre Windows 7 y Windows 10/11?
!! Porque Microsoft agregó cabezas de lista adicionales para drivers tempranos, ELAM y soporte TPM (`EarlyLaunchListHead`, `CoreDriverListHead`, `TpmCoreDriverListHead`), desplazando `Extension` desde `+0x098` en versiones antiguas hasta `+0x0F0` en Windows 10 22H2 y Windows 11 23H2/24H2; siempre debe confirmarse contra el PDB del build.

?? ¿Por qué un bootkit suele enganchar `ExitBootServices` y cómo detecta *Measured Boot* una manipulación en la cadena de arranque?
!! Enganchar `ExitBootServices` le permite intervenir justo cuando `winload.efi` ya mapeó `ntoskrnl.exe` pero antes de cederle la ejecución, para desactivar DSE o inyectar hooks previos a PatchGuard. Con *Measured Boot*, el firmware y el cargador miden los hashes SHA-256 de cada etapa en los registros PCR 0–7 del TPM, haciendo detectable cualquier alteración ante atestación remota.

:::{nota} Puerta optativa
Podés explicar cada etapa desde el firmware DXE hasta `KiSystemStartup`, localizar `gST` y `BootServices (+0x60)` en el desensamblado de un binario `.efi`, leer los campos clave de `LOADER_PARAMETER_BLOCK` en WinDbg y explicar cómo *Secure Boot* y *Measured Boot* (TPM PCRs) protegen e inventarían esa secuencia.
:::

## Fuentes

- UEFI Forum: *UEFI Specification* (capítulos sobre `EFI_SYSTEM_TABLE` y `EFI_BOOT_SERVICES` / `ExitBootServices`) y proyecto abierto EDK2 (`MdePkg`).
- Microsoft Learn: [Windows UEFI Firmware Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/boot-and-uefi), [Secure the Windows boot process](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process).
- Símbolos oficiales de Windows: `ntoskrnl.pdb` (`nt!_LOADER_PARAMETER_BLOCK`, `nt!_KLDR_DATA_TABLE_ENTRY`) y Russinovich, M., Solomon, D., & Ionescu, A., *Windows Internals*.

:::{nota} Etiquetas
**Núcleo conceptual:** cadena de arranque, traspaso firmware-SO e integridad de carga. **Conocimiento externo:** convención UEFI x64, estructura `LOADER_PARAMETER_BLOCK` (Win10/11) y arquitectura de bootkits / Measured Boot. **Ejemplo ilustrativo:** listado ensamblador `EfiMain` y diagrama de arranque. **Laboratorio verificado:** no; offsets de `LOADER_PARAMETER_BLOCK` sujetos a verificación por PDB.
:::
