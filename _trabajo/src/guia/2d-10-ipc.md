---
title: "2D.10 · IPC en Windows: named pipes, RPC y ALPC"
description: "Distinguir mecanismos de comunicación entre procesos y revisar nombres, permisos, instancias, impersonación, endpoints y controles RPC sin explotación."
etapa: "Etapa 2 · 2D · Windows internals (optativa)"
---

# IPC en Windows: named pipes, RPC y ALPC

:::{aviso} Rama optativa 2D
Se analizan mecanismos en programas propios o didácticos. No se buscan endpoints de terceros para enviarles datos ni se enseña a abusarlos.
:::

:::{nota} Propósito
Reconocer IPC por evidencia estática/dinámica y explicar qué controles separan al cliente del servidor. Al terminar deberías poder decir, para un canal propio, **quién puede abrirlo**, **quién puede hacerse pasar por servidor**, **con qué identidad actúa** el servidor al atender y **qué valida** antes de procesar un mensaje.
:::

**Prerrequisitos**

- *Obligatorios:* procesos e hilos ([1.3](01-procesos.html)); objetos, handles, tokens y ACL ([2D.1](2d-01-objetos.html)).
- *Recomendados:* COM/RPC ([2D.6](2d-06-com-interfaces.html), [2D.8](2d-08-dcom-rpc.html)).

## Diferencias

- **Named pipe:** canal nombrado, local o de red según configuración; el nombre no es secreto. El servidor decide acceso con ACL y puede autenticar/impersonar clientes; revisá también framing, longitud y validación de mensajes.

Para reconstruir la estructura de los mensajes más allá del mecanismo IPC, seguí [4.5 · Reconstruir formatos y protocolos propios](../guia/04-formatos-protocolos.html).
- **RPC:** contrato de operaciones que puede comunicarse local o remotamente; el runtime gestiona transporte/marshalling según binding. Analizá interfaz, endpoint, identidad y autorización.
- **ALPC:** mecanismo local de bajo nivel usado por componentes de Windows. En reversing suele reconocerse por módulos, estructuras y trazas; la documentación pública del contrato es limitada y varía por versión. Se cubre conceptualmente, sin construir clientes de endpoints del sistema.

| | Named pipe | RPC | ALPC |
|---|---|---|---|
| Qué transporta | Bytes o mensajes | Llamadas a operaciones de una interfaz (IDL) | Mensajes locales del sistema |
| Dónde se ve | Nombre `\\.\pipe\…`, handles de tipo archivo | UUID y versión de interfaz, secuencia de protocolo, endpoint | Módulos y trazas; poca documentación pública |
| Control de acceso principal | Descriptor de seguridad del pipe | Autenticación + callback de seguridad + chequeos en cada operación | Interno del sistema |
| Lo que lees en un análisis | Creación, apertura, ACL, modo, impersonación | Registro de interfaz, flags, protocolos, autenticación | Que existe, quién lo usa y qué evento registra |

## Named pipes en detalle

**Nombres y alcance.** Un servidor crea `\\.\pipe\nombre` con `CreateNamedPipe`; el nombre no distingue mayúsculas y cualquiera que lo conozca puede **intentar** abrirlo. Un cliente de otro equipo puede llegar por la red con `\\servidor\pipe\nombre`, salvo que el servidor cree la instancia con `PIPE_REJECT_REMOTE_CLIENTS`, que rechaza automáticamente las conexiones remotas.

**Descriptor de seguridad.** Si el servidor pasa `NULL`, el pipe recibe un descriptor por defecto que, según la documentación, da control total a LocalSystem, a los administradores y al creador, y **lectura** a Everyone y a la cuenta anónima. Un servidor que atiende solo a su sesión puede restringir el acceso con el *logon SID*; Microsoft lo recomienda para impedir accesos desde otras sesiones o equipos.

**Quién puede ser servidor.** Para crear una instancia hace falta el derecho `FILE_CREATE_PIPE_INSTANCE` sobre el pipe. La documentación advierte que `FILE_GENERIC_WRITE` incluye ese derecho (comparte valor con `FILE_APPEND_DATA`), así que una ACL que da “escritura genérica” también deja **crear instancias**. Si el servidor real crea la primera con `FILE_FLAG_FIRST_PIPE_INSTANCE`, la llamada falla con `ERROR_ACCESS_DENIED` cuando el nombre ya existe: es la forma documentada de detectar que otro proceso ocupó el nombre antes.

**Modo.** Un pipe de tipo **mensaje** conserva los límites de cada escritura; uno de tipo **byte** no. El lado cliente arranca en modo byte aunque el servidor sea de mensajes. Para el análisis, esto define cómo hay que leer el protocolo: con mensajes, cada `WriteFile` es una unidad; con bytes, el protocolo necesita su propio *framing* (longitud, delimitador) y es ahí donde se validan tamaños.

**Impersonación.** El servidor puede llamar a `ImpersonateNamedPipeClient` para actuar con el token del cliente y volver a su propia identidad con `RevertToSelf`. Por defecto la impersonación es al nivel `SecurityImpersonation`, pero el **cliente** puede limitarla al abrir el pipe con `CreateFile` y la bandera `SECURITY_SQOS_PRESENT` (por ejemplo, a nivel identificación). Para el análisis importan tres preguntas: ¿el servidor impersona? ¿revierte en todas las rutas, incluidos los errores? ¿qué nivel pidió el cliente?

| Qué revisar en un pipe propio | Evidencia | Señal a explicar |
|---|---|---|
| Nombre y proceso creador | Handle en el proceso servidor, argumentos de `CreateNamedPipe` | Nombre predecible usado por un servicio privilegiado |
| Descriptor de seguridad | DACL pasada al crear (o `NULL`) | Descriptor por defecto o ACL con `FILE_GENERIC_WRITE` amplio |
| Primera instancia | `FILE_FLAG_FIRST_PIPE_INSTANCE` en la primera creación | Sin la bandera, otro proceso pudo ocupar el nombre antes |
| Clientes remotos | `PIPE_REJECT_REMOTE_CLIENTS` | Aceptación remota sin necesidad |
| Modo y framing | Tipo byte/mensaje, prefijo de longitud | Longitud leída del mensaje sin tope |
| Impersonación | `ImpersonateNamedPipeClient` / `RevertToSelf` | Rutas de error sin `RevertToSelf` |

## RPC en detalle

Una interfaz RPC se define en **IDL** con un UUID y una versión; MIDL genera los stubs de cliente y servidor. El servidor registra la interfaz y elige **secuencias de protocolo**: `ncalrpc` (local), `ncacn_np` (sobre named pipes) o `ncacn_ip_tcp` (TCP, normalmente con endpoint dinámico resuelto por el mapeador de 2D.8).

Tres lecturas de seguridad que Microsoft documenta y que cambian conclusiones:

- **Los endpoints no aíslan interfaces.** En un proceso con varios servidores RPC, *todas* las interfaces son invocables por *todos* los endpoints del proceso. Que tu componente registre solo `ncalrpc` no impide que lo llamen por un pipe o un socket que abrió otro componente del mismo proceso. Por eso un descriptor de seguridad sobre un endpoint no es un control efectivo; la recomendación es un **callback de seguridad** que verifique protocolo e identidad en cada llamada.
- **Registrar autenticación no la exige.** `RpcServerRegisterAuthInfo` agrega una **opción** de autenticación, no un requisito: un cliente no autenticado que podía conectarse sigue pudiendo, aunque luego fallen funciones como `RpcImpersonateClient`.
- **Flags de registro.** Con `RpcServerRegisterIf2`/`Ex`/`3`, `RPC_IF_ALLOW_LOCAL_ONLY` rechaza clientes remotos (con las excepciones que detalla la documentación para `ncacn_np`), y `RPC_IF_ALLOW_SECURE_ONLY` exige un nivel de autenticación mayor que *none*, **sin** garantizar que el usuario sea privilegiado: puede ser una cuenta de invitado.

Microsoft remarca que `ncalrpc` no es “seguro por ser local”: en un servidor de terminales, cientos de usuarios pueden llegar a un servicio local.

### Anatomía Interna de Stubs RPC y Decodificación de NDR (Format Strings)

Para el analista de ingeniería inversa que audita un binario sin símbolos ni archivos `.idl`, cuando el servidor invoca `RpcServerRegisterIf` / `RpcServerRegisterIf2` / `RpcServerRegisterIfEx`, el primer argumento (`IfSpec` en `RCX` en x64) apunta a `RPC_SERVER_INTERFACE` en `.rdata` o `.data` (*Hecho confirmado*, `rpcndr.h`):

| Offset (x64) | Campo en `RPC_SERVER_INTERFACE` | Tipo y significado en IDA / Ghidra |
|---|---|---|
| `+0x00` | `Length` | Tamaño de estructura (`0x60` / 96 bytes en x64). |
| `+0x04` | `InterfaceId` | `RPC_SYNTAX_IDENTIFIER` (20B): `SyntaxGUID` (16B) + `MajorVersion` (2B) + `MinorVersion` (2B). |
| `+0x30` | `DispatchTable` | `PRPC_DISPATCH_TABLE`: cantidad (`DispatchTableCount`) y despachador NDR (`NdrServerCall2` / `NdrServerCallAll`). |
| `+0x50` | `InterpreterInfo` | Puntero hacia `MIDL_SERVER_INFO` (`+0x00 pStubDesc`, `+0x08 DispatchTable`, `+0x10 ProcFormatString`, `+0x18 FmtStringOffset`). |

Siguiendo `InterpreterInfo` hacia `MIDL_SERVER_INFO`, el campo **`+0x08 DispatchTable`** contiene el arreglo directo de punteros a las funciones C del servidor (`ServerRoutineTable[0..N-1]`). Herramientas como **`RpcView`** o scripts de **IDAPython** automatizan la navegación `InterfaceId -> InterpreterInfo -> DispatchTable`.

```text
RPC_SERVER_INTERFACE (+0x00 Length = 0x60 en x64):
   +0x04: InterfaceId.SyntaxGUID (UUID 16B) + SyntaxVersion
   +0x30: DispatchTable (PRPC_DISPATCH_TABLE -> NdrServerCall2)
   +0x50: InterpreterInfo (Ptr64 -> MIDL_SERVER_INFO)
          +-- +0x00: pStubDesc (Ptr64 -> MIDL_STUB_DESC)
          +-- +0x08: DispatchTable (ServerRoutineTable[0..N-1])
          +-- +0x10: ProcFormatString (formatos NDR)
          +-- +0x18: FmtStringOffset (indices a ProcFormatString)
```

#### Decodificación de `ProcFormatString` y `TypeFormatString`
El compilador MIDL genera secuencias de bytes compactas que codifican los parámetros de cada método mediante la máquina de tipos de **NDR (Network Data Representation)**:
1. **Cabecera de Procedimiento:** En `ProcFormatString`, cada rutina arranca con una cabecera de 6 bytes en modo `-Oicf` que define el tamaño del marco en la pila (`stack_size`) y el número de parámetros.
2. **Descriptores de Parámetros (6 bytes por parámetro):**
   - **Flags de Dirección:** Los primeros 2 bytes indican si el parámetro es entrante o saliente (`0x0048` = `[in]`, `0x0158` = `[out]`, `0x0050` = `[in, out]`).
   - **Offset en el Stack:** Los siguientes 2 bytes indican la posición relativa en el marco de la llamada.
   - **Descriptor de Tipo:** Los 2 bytes finales contienen el tipo básico (`FC_LONG = 0x08`, `FC_HYPER = 0x0b`, `FC_CHAR = 0x02`) o un offset relativo hacia **`TypeFormatString`** (almacenado en `MIDL_STUB_DESC+0x28`).
3. **Tipos Complejos en `TypeFormatString`:**
   - `0x11` (`FC_RP`): Puntero de referencia (no puede ser nulo).
   - `0x12` (`FC_UP`): Puntero único (puede ser nulo).
   - `0x21` (`FC_C_CSTRING`): Cadena ASCII conformante terminada en nulo (`char*`).
   - `0x22` (`FC_C_WSTRING`): Cadena UTF-16 conformante terminada en nulo (`wchar_t*`).
   - `0x1A` (`FC_BOGUS_STRUCT`): Estructura compleja con alineación manual y punteros anidados.

El laboratorio `plantillas_codigo/rpc_com_server_lab.c` y su definición `rpc_com_server_lab.idl` permiten compilar un servidor local sobre `ncalrpc` y verificar la disposición exacta de estas tablas en memoria.

## ALPC

ALPC (*Advanced Local Procedure Call*) es el mecanismo interno de mensajes locales sobre el que corren RPC local (`ncalrpc`) y múltiples servicios del sistema. Su contrato binario interno no es una API pública documentada y varía entre versiones de Windows, así que debés enfocarte en **reconocerlo y auditarlo en modo lectura** sin enviar mensajes a puertos del sistema.

:::{aviso} Declaración de entorno (inspección ALPC)
`Laboratorio verificado: no; requiere VM/toolchain`. Requiere Sysinternals `handle64.exe` con privilegios administrativos y/o una sesión de depuración de kernel en WinDbg (`!alpc`).
:::

1. **Primitivas de `ntdll.dll` y espacio de nombres `\RPC Control\`:** el servidor publica un objeto `ALPC Port` con `ntdll!NtAlpcCreatePort` (usualmente bajo `\RPC Control\<Puerto>` o `\Sessions\<N>\BaseNamedObjects\...`), el cliente conecta con `ntdll!NtAlpcConnectPort` / `NtAlpcConnectPortEx` y ambos intercambian datos con `ntdll!NtAlpcSendWaitReceivePort`.
2. **Cabecera `PORT_MESSAGE` en memoria (`+0x00..+0x27`, 40 bytes en x64 / 24 bytes en x86):**

```c
typedef struct _PORT_MESSAGE_X64 {
    USHORT    DataLength;            // +0x00: bytes de payload
    USHORT    TotalLength;           // +0x02: 0x28 + DataLength
    USHORT    Type;                  // +0x04: REQUEST(1), REPLY(2)
    USHORT    DataInfoOffset;        // +0x06
    PVOID     ClientIdUniqueProcess; // +0x08: PID emisor
    PVOID     ClientIdUniqueThread;  // +0x10: TID emisor
    ULONG     MessageId;             // +0x18: ID correlativo
    ULONG     Reserved;              // +0x1C
    ULONG_PTR ClientViewSize;        // +0x20: cabecera total = 0x28
} PORT_MESSAGE_X64;
```

3. **Inspección en solo lectura (`handle64.exe` en user-mode y `!alpc` en WinDbg):**

```text
:: Enumeracion en user-mode (consola elevada) con Sysinternals
C:\Tools\Sysinternals> handle64.exe -a -p lsass.exe | findstr /i "ALPC"
   228: ALPC Port      \RPC Control\lsapolicylookup
   254: ALPC Port      \RPC Control\lsasspirpc
   2bc: ALPC Port      \RPC Control\protected_storage

:: En WinDbg de kernel (!alpc): puertos de conexion, detalle y clientes
kd> !alpc /lpl
  Port: ffffb609148e2c90 Owner: lsass.exe    Name: \RPC Control\lsasspirpc
  Port: ffffb60915a1a080 Owner: services.exe Name: \RPC Control\spoolerpc

kd> !alpc /lpp <dir_EPROCESS>  ; puertos creados/conectados por proceso
kd> !alpc /p ffffb609148e2c90  ; detalle de ConnectionPort y colas
kd> !alpc /c ffffb609148e2c90  ; clientes conectados (ej. svchost.exe)
kd> !alpc /m <dir_Message>     ; decodifica un mensaje en vuelo
```

De forma complementaria, `!alpc /p <dir_PortObject>` expone la estructura `_KALPC_PORT` completa (`OwnerProcess`, `ServerCommunicationPort`, `ClientCommunicationPort`, longitudes de colas y flags) y `!alpc /c` lista cada par servidor-cliente en `CommunicationInfo` sin perturbar los mensajes.

## Ejemplo trabajado

*(Ejemplo ilustrativo de una app propia; los valores no son una captura.)*

```text
BlocClient -> \\.\pipe\BlocLab.Status -> BlocService
Mensaje: {version=1, request=GET_STATUS}
Respuesta: {status=READY}
Seguridad: ACL permite al usuario de la sesión; no acepta datos arbitrarios
```

El pipe sugiere el transporte, pero hay que confirmar el proceso propietario, ACL, modo de lectura y formato del protocolo. Un nombre predecible no implica vulnerabilidad por sí solo.

Ficha del análisis, separando observación de inferencia:

| Dato | Valor (ilustrativo) | Tipo |
|---|---|---|
| Creador del pipe | `BlocService.exe`, cuenta de servicio de laboratorio | Observación (handle y proceso) |
| Flags de creación | `PIPE_ACCESS_DUPLEX`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_TYPE_MESSAGE`, `PIPE_REJECT_REMOTE_CLIENTS` | Observación (argumentos en el código o el depurador) |
| DACL | Lectura/escritura al *logon SID* de la sesión; control total a SYSTEM | Observación (`GetSecurityInfo` en el lab) |
| Impersonación | `ImpersonateNamedPipeClient` antes de leer la configuración del usuario; `RevertToSelf` en salida normal y en error | Observación en código propio |
| Validación | Mensaje de tamaño fijo; versión distinta de 1 se rechaza | Observación en código propio |
| “Ningún otro proceso puede hacerse pasar por servidor” | — | Inferencia: la sostiene la primera instancia con bandera, no el nombre |

## Práctica

Con un cliente/servidor propios ya preparados:

1. Listá los pipes visibles en la VM solo para ubicar el tuyo (en PowerShell, `Get-ChildItem \\.\pipe\` muestra nombres) y no abras pipes ajenos.
2. Inspeccioná en Process Explorer/Procmon la apertura del endpoint y seguí una sola solicitud inocua. Capturá nombre, PID, operación, respuesta y ACL observada.
3. Completá la tabla “Qué revisar en un pipe propio” con evidencia del código o del depurador.
4. Para RPC, usá el propio contrato local: anotá UUID/versión, secuencias de protocolo registradas, flags de registro y si hay callback de seguridad.
5. Para ALPC, describí una traza/documentación existente, sin enviar mensajes.

## Entregable

Diagrama de dos procesos, mecanismo IPC, endpoint, identidad, controles, esquema del mensaje y evidencia. Incluí la tabla de revisión del pipe (o del registro RPC) con observación/inferencia. Ocultá datos personales; no registres payloads sensibles.

## Repaso

?? ¿Un named pipe siempre es local?
!! No. Puede ser local o accesible por red según cómo se publique y la configuración del sistema/servidor; `PIPE_REJECT_REMOTE_CLIENTS` rechaza clientes remotos.

?? ¿Qué diferencia RPC de un pipe?
!! RPC expresa una llamada mediante una interfaz; un pipe es un canal de bytes/mensajes. RPC puede usar distintos transportes.

?? ¿Qué derecho permite crear instancias de un pipe y por qué importa una ACL con escritura genérica?
!! `FILE_CREATE_PIPE_INSTANCE`. `FILE_GENERIC_WRITE` lo incluye, así que esa ACL también permite crear instancias, es decir, actuar como servidor.

?? ¿Para qué sirve `FILE_FLAG_FIRST_PIPE_INSTANCE`?
!! Hace que la creación falle si el nombre ya existe, así el servidor detecta que otro proceso ocupó el pipe antes.

?? ¿Quién controla hasta dónde puede impersonar un servidor de pipe?
!! El cliente, con `SECURITY_SQOS_PRESENT` y el nivel elegido al abrir el pipe; por defecto es `SecurityImpersonation`.

?? Un servidor RPC registra solo `ncalrpc`. ¿Queda accesible solo localmente?
!! No necesariamente: en un proceso con otros servidores RPC, la interfaz es invocable por cualquier endpoint del proceso. Se controla con un callback de seguridad.

?? ¿`RpcServerRegisterAuthInfo` impide que se conecten clientes no autenticados?
!! No. Agrega una opción de autenticación, no un requisito; hacen falta chequeos propios.

?? ¿Por qué ALPC se trata como concepto?
!! Es una interfaz interna de bajo nivel con contratos menos estables; el curso enseña reconocimiento, no clientes de endpoints del sistema.

:::{nota} Puerta optativa
Podés distinguir pipe, RPC y ALPC, seguir un intercambio propio, revisar ACL, primera instancia, clientes remotos, modo e impersonación de un pipe, y explicar por qué en RPC el control debe estar en el callback de seguridad y no en el endpoint.
:::

:::{nota} Lo que queda fuera
El protocolo de red de los pipes remotos, el formato interno de RPC (NDR), los mensajes ALPC, mailslots, memoria compartida y otros mecanismos IPC no se desarrollan. No se enseña a enviar datos a pipes ni a endpoints RPC ajenos.
:::

## Fuentes

- Microsoft Learn: [Interprocess Communications](https://learn.microsoft.com/en-us/windows/win32/ipc/interprocess-communications), [Named Pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes), [RPC](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page), [ALPC ETW class](https://learn.microsoft.com/en-us/windows/win32/etw/alpc).
- Microsoft Learn, pipes: [CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea), [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [Impersonating a Named Pipe Client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client), [Named Pipe Type, Read, and Wait Modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes).
- Microsoft Learn, RPC seguro: [Writing a Secure RPC Client or Server](https://learn.microsoft.com/en-us/windows/win32/rpc/writing-a-secure-rpc-client-or-server), [Be Wary of Other RPC Endpoints Running in the Same Process](https://learn.microsoft.com/en-us/windows/win32/rpc/be-wary-of-other-rpc-endpoints-running-in-the-same-process), [RpcServerRegisterAuthInfo doesn't deny unauthorized users](https://learn.microsoft.com/en-us/windows/win32/rpc/common-mistake-assuming-rpcserverregisterauthinfo-prevents-unauthorized-users-from-calling-your-server), [Interface Registration Flags](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags), [Protocol Sequence Constants](https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants).
- **Fundamentos previos:** call stack y procesos en [1.3](01-procesos.html); DCOM/RPC en [2D.8](2d-08-dcom-rpc.html).

:::{nota} Etiquetas
**Núcleo conceptual:** procesos e IPC general. **Conocimiento externo:** IPC Windows, seguridad de named pipes y RPC. **Ejemplo ilustrativo:** protocolo y ficha BlocLab. **Laboratorio verificado:** no; ejemplo propio propuesto.
:::
