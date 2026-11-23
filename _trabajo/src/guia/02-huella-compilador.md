---
title: "2.13 · Huella de compilador: saber con qué se hizo"
description: "Reconocer si un binario es MSVC, MinGW, Delphi, VB6, MFC, Go o Rust por sus imports, strings, runtime y estructuras — para leerlo con la estrategia correcta."
etapa: "Etapa 2 · Windows intermedio"
---

# Huella de compilador: saber con qué se hizo

:::{nota} Objetivo de la lección
Antes de leer una sola instrucción, saber **con qué compilador/runtime** se armó el binario, porque eso cambia todo: dónde está la lógica, cómo se ven las llamadas, qué estructuras esperar. **Prerrequisitos:** PE e imports (1.4), IDA (2.7), MFC (2.12).
:::

## Por qué mirar esto primero

El mismo programa en C se ve **distinto** según el compilador, y un programa de Delphi o Visual Basic no se parece en nada a uno de C. Identificar la huella te ahorra horas: te dice si vas a encontrar un `main` clásico, un runtime que rutea todo, p-code en vez de nativo, o una maraña de clases. Es lo primero que hace un analista con experiencia (**recomendación editorial**).

## Tabla de huellas

**Conocimiento externo** (pistas que se confirman en los imports, strings y secciones del PE):

| Compilador / runtime | Pistas típicas |
|---|---|
| **MSVC** (Visual C++) | **Rich header** en la cabecera (ver [2.14](02-pe-fino.html)); `__security_cookie`, `__scrt_common_main`, `__acrt_*`; ruta a un `.pdb`; runtime `vcruntime###.dll`/`ucrtbase.dll` |
| **MinGW/GCC** | `msvcrt.dll`, `__mingw_*`, `libgcc_s_*`, `___chkstk_ms`, sección `.eh_frame`; **sin** Rich header; strings de rutas tipo `/mingw/...` |
| **Delphi** | Strings `Sysutils`, `System`, `Classes`, `TForm`, `TObject`; símbolos con `@`; VMT (tabla de métodos) al inicio del objeto; secciones `.itext`/`.data` particulares |
| **Visual Basic 6** | Import de `MSVBVM60.DLL`; funciones `__vba*`; strings `Project1`/`Form1`; puede ser **p-code** (interpretado) o nativo |
| **MFC** (sobre MSVC) | `mfc###u.dll` (p. ej. `mfc140u.dll`), `AfxWinInit`/`AfxWinMain`, clases `CWnd`/`CDialog`/`CString`, message map (ver [2.12](02-mfc.html)) |
| **Go** | Binario grande y enlazado estáticamente, con pocos imports; cadena `Go build ID`; nombres de paquetes y funciones como `main.main`, `runtime.` o `fmt.` visibles aunque no haya símbolos de depuración; sección o datos con la tabla `pclntab` |
| **Rust** | Rutas de código fuente en mensajes de pánico (`src/main.rs`, `library/core/src/...`); símbolos con mangling `_ZN...E` (antiguo) o `_R...` (v0); mensajes como «called `Option::unwrap()` on a `None` value»; con el target `-msvc` puede traer **Rich header** del linker de Microsoft |

Regla práctica: **mirá primero los imports** (qué DLLs de runtime trae) y las **strings** (nombres de clases/módulos); con eso ya ubicás la familia.

### Triage rápido de instaladores y wrappers frecuentes en Windows

Muchas muestras empaquetadas como instaladores o wrappers envuelven la carga real en contenedores estándar; extraer en solo lectura evita perder tiempo revirtiendo el stub genérico (**conocimiento externo**):

| Instalador / Wrapper | Huellas rápidas (strings / secciones / recursos) | Extracción estática recomendada |
|---|---|---|
| **NSIS** (Nullsoft) | Strings `NullsoftInst` / `Nullsoft.NSIS.exehead`, sección `.ndata` y payload comprimido en overlay | **`7-Zip`** (`7z x setup.exe`) extrae archivos y stub sin ejecutar |
| **Inno Setup** | Banner `Inno Setup Setup Data` / `JR.Inno.Setup` en recursos (runtime típico en Delphi) | **`innoextract`** (`innoextract -d ./out setup.exe`) recupera ejecutables y script |
| **MSI** (Windows Installer) | Magic OLE Compound File (`D0 CF 11 E0 A1 B1 1A E1`), tablas `CustomAction` y flujo `Binary` | **`lessmsi`** (extracción de streams) / **`Orca`** (inspección de tablas SQL del `.msi`) |
| **AutoIt** (v3 compilado) | Recurso `RT_RCDATA` `SCRIPT`, firma `AU3!EA06` (o `AU3!EA05`) y stub intérprete C++ | Inspección del recurso `SCRIPT` / herramientas de extracción AutoIt en VM aislada |

## Dos casos que cambian la estrategia

- **VB6 p-code vs. nativo.** Si es p-code, el código "real" no es x86: es bytecode que interpreta `MSVBVM60.DLL`. Leer el x86 directo no sirve; hay que usar herramientas específicas de VB. Reconocerlo temprano evita perder tiempo.
- **Delphi.** Las APIs no se llaman como en C: el objeto trae su **VMT** al inicio y los métodos se resuelven por tabla. Esperar un `main` con `CreateWindow` directo te confunde.

En recopilaciones dispersas esto suele figurar como material suelto, no como lección estructurada: en `Teorias_Numeradas` hay **decenas de títulos de Delphi** y **varios de Visual Basic/VB6, p-code y Java** ([índice clasificado](../teorias.html)). Son conteos **por subcadena del título** (aproximados, sin abrir los contenedores): orientan para profundizar, no son prueba. El único runtime trabajado a fondo en el curso es **MSVC/C++** (y MFC en la [2.12](02-mfc.html), observado en el cap. 39: {{src:CLS_resultados_intermedios/transcripciones/extraidos/Reversing desde cero (Ricardo y Solid)/Ricardo Narvaja y Solid - Reversing desde cero_39 TIPS 2 MFC_TIPS 2 MFC.txt|Reversing desde cero, cap. 39}}).

## Lenguajes que no se leen como C: huella rápida de Go, Rust y Delphi

Los tres producen código nativo x86/x64, así que IDA y Ghidra los abren sin problema. Todo este apartado es **conocimiento externo** al material de reversing clásico. En esta lección dejamos solo la **huella rápida de triage** para Go y Rust (para profundizar en su ABI de registros, `pclntab`, `itab`, *trait objects* y *niche optimization*, continuá en [**Lección 2.32 · Go y Rust en profundidad**](02-go-rust.html)):

- **Go (triage rápido):** ejecutables grandes (varios MB) por el runtime embebido, strings `.go` / `Go build ID` y tabla `pclntab` intacta aunque esté «stripeado»; cadenas sin terminador nulo y prólogo con chequeo de pila antes de la lógica. Analizalo a fondo en [2.32](02-go-rust.html).
- **Rust (triage rápido):** trampa frecuente en Windows: con el target `-msvc` trae Rich header e importa `vcruntime140.dll` como C++, pero lo delatan rutas `.rs` en *panics* (`src/main.rs`), símbolos `_ZN...E` / `_R...` y chequeos de límites frecuentes. Analizalo a fondo en [2.32](02-go-rust.html).

**Delphi** (amplía la fila de la tabla).

- **Formularios como recursos.** Los formularios (`TForm`) se guardan como recursos `RCDATA` que empiezan con la firma `TPF0`; ahí están los nombres de los controles y los **nombres de los manejadores de eventos** (por ejemplo `Button1Click`), que te llevan directo a la lógica.
- **Convención `register`.** En Delphi de 32 bits la convención por defecto pasa los tres primeros argumentos en `EAX`, `EDX` y `ECX`, no en el stack: un método recibe `Self` en `EAX`. Si leés el listado esperando `stdcall`, los argumentos "desaparecen".
- **Cadenas con cabecera.** Los `string` largos de Delphi guardan contador de referencias y longitud **antes** del primer carácter, así que el puntero apunta al texto pero hay datos en offsets negativos.
- **RTTI y VMT.** Los nombres de clases y la tabla de métodos virtuales permiten reconstruir jerarquías; existen herramientas específicas para Delphi que lo automatizan.

:::{aviso} Pistas, no pruebas
Una huella es un **indicio**, no un certificado. La **ausencia de Rich header** sugiere que no es MSVC, pero no **demuestra** MinGW (podría ser otro linker o estar removido). Y una app **MFC enlazada estáticamente** puede **no** importar `mfc###u.dll`. Confirmá siempre con varias señales juntas.
:::

## Ejemplo paso a paso: el mismo `hola.c`, dos compiladores

*(Ejemplo **ilustrativo**: imports representativos; varían según versión.)*

El mismo programa compilado en MSVC y en MinGW deja huellas distintas:

```text
MSVC (cl hola.c)                     MinGW (gcc hola.c)
──────────────────────────           ──────────────────────────
Rich header: presente                Rich header: AUSENTE
Imports:                             Imports:
  VCRUNTIME140.dll                     msvcrt.dll
    __C_specific_handler                 __getmainargs, __set_app_type
    memcpy, __current_exception          _onexit, __p__fmode
  api-ms-win-crt-stdio-l1-1-0.dll      KERNEL32.dll
    __stdio_common_vfprintf          Secciones: .text .data .rdata
  KERNEL32.dll                                   .eh_frame  ← GCC
Secciones: .text .rdata .data        Símbolos: __mingw_*, ___chkstk_ms
  (sin .eh_frame)
```

Con solo mirar imports y secciones ya decidís: Rich header + `api-ms-win-crt-*` + `__C_specific_handler` ⇒ **MSVC**; `msvcrt.dll` + `__mingw_*` + `.eh_frame` y sin Rich header ⇒ **MinGW** (recordá la salvedad de arriba: es indicio, no prueba).

> **Ampliación editorial basada en fuentes externas — Reversing de ejecutables empaquetados de Python (`PyInstaller`) y aplicaciones Electron (`ASAR`)**
>
> Un error frecuente de triage ocurre cuando el analista abre en IDA o Ghidra un `.exe` de varios megabytes y empieza a desensamblar funciones en C como `pyi_main`, `pyi_arch_open_archive` o llamadas a `uv_run`, creyendo que está viendo la lógica del programa, cuando en realidad está frente al *bootloader* nativo de un lenguaje interpretado (**Hecho confirmado**):
>
> 1. **Ejecutables de Python empaquetados con `PyInstaller`:**
>    PyInstaller empaqueta el intérprete (`python3XX.dll`), las extensiones `.pyd` y los scripts compilados a bytecode (`.pyc`) dentro de un archivo `CArchive` adjunto al final del PE (en el *overlay* o como recurso).
>    * **Huella estática inequívoca:**
>      * Strings en `.rdata`: `"PyInstaller: FormatMessageW failed."`, `"_MEIPASS2"`, `"python311.dll"` (o `310`, `312`, `313`).
>      * Magic de la estructura `COOKIE` buscando desde el final del archivo: los 8 bytes `4D 45 49 0C 0B 0A 0B 0E` (`MEI\x0c\x0b\x0a\x0b\x0e`).
>    * **Flujo de extracción y decompilación en laboratorio (sin ejecutar el binario):**
>      1. **Extraer el contenedor:** Ejecutar `pyinstxtractor.py` sobre una copia del `.exe`:
>         ```powershell
>         python pyinstxtractor.py muestra_pyinstaller.exe
>         ```
>         Esto crea la carpeta `muestra_pyinstaller.exe_extracted/`, indica la versión exacta de Python (p. ej. `Python 3.11`) y señala los posibles puntos de entrada (`Possible entry points: main.pyc`).
>      2. **Estructura del encabezado `.pyc` (Python 3.7 a 3.13+):** Todo archivo `.pyc` válido en Python 3.7+ tiene una cabecera de **16 bytes** antes del objeto `code` serializado con `marshal`:
>         * `+0x00` (4B): *Magic number* de la versión de Python (p. ej. `A7 0D 0D 0A` en Python 3.11; `CB 0D 0D 0A` en 3.12).
>         * `+0x04` (4B): Bit field (`0x00000000` para timestamp).
>         * `+0x08` (4B): Timestamp o hash parcial.
>         * `+0x0C` (4B): Tamaño del archivo fuente `.py` original.
>         *(Nota: versiones recientes de `pyinstxtractor.py` ya reconstruyen estos 16 bytes automáticamente al extraer).*
>      3. **Decompilar o desensamblar el bytecode:** Con `pycdc` (*Decompyle++*) se recupera código fuente `.py`; si el bytecode es de Python 3.11/3.12/3.13 y el decompilador falla en algún opcode nuevo, el módulo estándar `dis` + `marshal` corrido con **esa misma versión de Python** muestra el desensamblado exacto e infalible:
>         ```python
>         # volcar_pyc.py — ejecutar con la MISMA versión menor de Python que informó pyinstxtractor
>         import dis, marshal
>
>         with open("main.pyc", "rb") as f:
>             f.seek(16)  # salta los 16 bytes del encabezado .pyc (Python 3.7+)
>             code_obj = marshal.load(f)
>         dis.dis(code_obj)
>         ```
>
> 2. **Aplicaciones empaquetadas con Electron / Node.js (`app.asar`):**
>    * **Huella:** Binario PE enorme (> 100 MB) que importa `ffmpeg.dll`, `d3dcompiler_47.dll`, contiene strings de `Chromium` / `Node.js` y va acompañado de una carpeta `resources/` con un archivo `app.asar` (magic header con longitud JSON prefijada).
>    * **Extracción estática:** La lógica no está en el `.exe`, sino en el JavaScript dentro de `resources/app.asar`. Se extrae en modo lectura con `npx @electron/asar extract resources/app.asar ./codigo_extraido`.

## Práctica

En tu VM, con **programas propios**:

1. Compilá el **mismo** `hola.c` con **MSVC** (`cl`) y con **MinGW** (`gcc`). Abrí ambos en PE-bear/IDA.
2. Armá una tabla comparando: DLLs de runtime en imports, presencia de Rich header, strings de rutas, secciones (`.eh_frame` vs. no).
3. Si tenés cómo, compilá algo mínimo en **Delphi** o abrí un binario VB6 de práctica y buscá `MSVBVM60.DLL` o `TForm`/`TObject`.
4. Escribí en una línea, para cada binario, "esto es X porque veo Y".
5. Si tenés Go o Rust instalados, compilá un programa propio mínimo que compare una cadena ingresada con una fija. En el de Go, ubicá `main.main` y la comprobación de pila del inicio; en el de Rust, buscá las rutas `.rs` y mirá si hay Rich header. En ambos, encontrá la cadena fija y anotá dónde está su longitud.

::: {nota} Dónde profundizar cada lenguaje (Bloque 2E)
Esta lección enseña a identificar el compilador en el triage inicial. Para reconstruir tipos e interfaces (`itab`, `pclntab`) en Go y *trait objects* (`dyn Trait`), monomorfización y mangling `v0` en Rust, seguí a la lección **2.32 · Go y Rust en profundidad**. Para analizar `VBHeader`, llamadas `__vba*` y bytecode *p-code* en Visual Basic 6, consultá la lección **2.33 · VB6 y p-code**.
:::

## Preguntas de repaso

?? ¿Por qué conviene identificar el compilador antes de leer el código?
!! Porque determina **dónde está la lógica y cómo se ve**: un binario Delphi, uno VB6 p-code y uno MSVC se analizan de formas distintas. Saberlo evita buscar un `main` clásico donde no lo hay.

?? ¿Qué pista distingue MSVC de MinGW de un vistazo?
!! MSVC trae **Rich header** y runtime `vcruntime`/`ucrtbase` con `__security_cookie`; MinGW usa `msvcrt.dll`, símbolos `__mingw_*`, `.eh_frame` y **no** tiene Rich header.

?? Ves import de `MSVBVM60.DLL`. ¿Qué implica y qué riesgo hay?
!! Es **Visual Basic 6**. Riesgo: puede ser **p-code** (bytecode interpretado por esa DLL), así que leer el x86 directo no te muestra la lógica real; necesitás herramientas de VB.

?? ¿Cómo reconocés Delphi?
!! Strings como `Sysutils`/`System`/`Classes`/`TForm`/`TObject`, símbolos con `@` y la **VMT** al inicio de los objetos; las llamadas no se ven como en C.

?? Un binario tiene Rich header e importa `vcruntime140.dll`, pero aparecen rutas `src/main.rs`. ¿Qué es?
!! Probablemente **Rust** compilado con el target `-msvc`: el linker de Microsoft deja el Rich header y el runtime de C, pero las rutas `.rs` y los mensajes de pánico delatan el lenguaje. Es el ejemplo de por qué una sola pista no alcanza.

?? ¿Por qué en un binario de Go sin símbolos podés ver nombres como `main.main`?
!! Porque el runtime necesita la tabla `pclntab` (direcciones → funciones y líneas) para trazas de pila, perfilado y recolección de basura, y quitar los símbolos de depuración no la elimina.

?? En Delphi de 32 bits, ¿dónde llegan los primeros argumentos de un método?
!! En `EAX`, `EDX` y `ECX` (convención `register`); `Self` viene en `EAX`. Leerlo como `stdcall` hace que los argumentos parezcan faltar.

?? ¿Qué parte de esto corresponde a patrones clásicos y qué a compiladores modernos?
!! MFC está observado (cap. 39) y hay **títulos** de Delphi/VB/Java en `Teorias_Numeradas` (no leídos). La tabla de huellas de MSVC/MinGW/Delphi/VB6/Go/Rust y el apartado de lenguajes no-C son **conocimiento externo**.

:::{nota} Puerta de salida
Podés: (1) decir con qué compilador/runtime se hizo un binario y por qué; (2) distinguir MSVC de MinGW por imports/Rich header/secciones; (3) reconocer VB6 (y el riesgo de p-code) y Delphi; (4) justificar cada conclusión con una pista concreta del PE; (5) reconocer un binario de Go o de Rust y explicar qué cambia al leerlo (nombres recuperables, cadenas con longitud, comprobaciones del runtime).
:::

## Fuentes de esta lección

- {{src:CLS_resultados_intermedios/transcripciones/extraidos/Reversing desde cero (Ricardo y Solid)/Ricardo Narvaja y Solid - Reversing desde cero_39 TIPS 2 MFC_TIPS 2 MFC.txt|Reversing desde cero, cap. 39}} — MFC como capa sobre la API (huella de framework).
- [Teorias_Numeradas · clasificación](../teorias.html) — títulos de Delphi, Visual Basic/VB6, p-code y Java (conteo aproximado por subcadena del título); material para profundizar, no leído.
- Go (conocimiento externo): [paquete debug/gosym](https://pkg.go.dev/debug/gosym) y [diseño de la tabla de símbolos de Go 1.2](https://go.dev/s/go12symtab) — la tabla `pclntab` y por qué la necesita el runtime; [A Quick Guide to Go's Assembler](https://go.dev/doc/asm).
- Rust (conocimiento externo): [Symbol Mangling](https://doc.rust-lang.org/rustc/symbol-mangling/index.html) y [esquema v0](https://doc.rust-lang.org/rustc/symbol-mangling/v0.html); [tipo primitivo str](https://doc.rust-lang.org/std/primitive.str.html).
- Delphi: la convención `register`, la firma `TPF0` de los formularios y la cabecera de los `string` son conocimiento externo sin enlace verificado en esta revisión (la documentación de Embarcadero no respondió durante la verificación).

:::{nota} Capas de esta lección
**Núcleo conceptual:** la huella de MFC del capítulo 39 y los conteos por título de `Teorias_Numeradas`. **Conocimiento externo:** la tabla de huellas (Rich header, `MSVBVM60.DLL`, VMT de Delphi, `.eh_frame` de MinGW, Go y Rust), el caso p-code y las particularidades de lectura de Go, Rust y Delphi. **Recomendación editorial:** mirar imports y strings primero y la práctica comparativa MSVC/MinGW.
:::
