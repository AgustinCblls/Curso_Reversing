# -*- coding: utf-8 -*-
"""Maquetación editorial inteligente A4 y saltos manuales para todos los PDFs de CLS_Guia.

Equivalente unificado al motor editorial de Hacking_Etico_Español:
- Soporta marcas manuales <!-- salto -->, <!-- pagebreak --> y ::: salto en HTML y Markdown.
- Marca tablas compactas (<= 12 filas de cuerpo) con .tabla-compacta para evitar cortes
  a mitad de tabla, permitiendo que tablas largas (glosarios/catálogos) fluyan con thead repetido.
- Agrupa bloques H2 y H3 compactos (<= ~1 hoja A4) en .bloque-h2-compacto / .subtema-h3-compacto.
- En bloques extensos (> 1 hoja), protege el encabezado junto a su primer bloque sustancial en
  .arranque-inseparable usando cortes por índice exactos (sin pérdida de elementos).
- Une cierres breves ("Antes de avanzar" / "Preguntas de repaso" + "Referencias" / "Fuentes").
"""
import re

PRINT_CSS_MAQUETACION = """
p, li { orphans: 3; widows: 3; }
.print-sec h1, .print-sec h2, .print-sec h3, .print-sec h4 {
  break-after: avoid;
  page-break-after: avoid;
}
.bloque-h2-compacto,
.bloque-h2-unido,
.subtema-h3-compacto,
.arranque-inseparable,
.tabla-compacta,
.hoja-compacta .tabla {
  break-inside: avoid;
  page-break-inside: avoid;
}
.salto-pagina-manual {
  break-before: page;
  page-break-before: always;
  height: 0;
  margin: 0;
  padding: 0;
}
.print-sec thead { display: table-header-group; }
.print-sec tr { break-inside: avoid; page-break-inside: avoid; }
.print-sec td a, .print-sec td code { overflow-wrap: anywhere; }
"""

_SALTO_DIV = '<div class="salto-pagina-manual" aria-hidden="true"></div>'


def _strip_html(s):
    return re.sub(r"<[^>]+>", "", s)


def _html_divs_balanceados(fragmento):
    opens = len(re.findall(r"<div\b", fragmento, flags=re.I))
    closes = len(re.findall(r"</div\s*>", fragmento, flags=re.I))
    return opens == closes


def preprocesar_saltos_html(html_str):
    """Convierte comentarios <!-- salto --> / <!-- pagebreak --> o ::: salto fuera de <pre>/<code>."""
    if not html_str:
        return html_str

    protegidos = []

    def _guardar(m):
        protegidos.append(m.group(0))
        return f"\x00CLS_PRE_{len(protegidos) - 1}\x00"

    trabajo = re.sub(r"<pre\b[^>]*>.*?</pre>", _guardar, html_str, flags=re.S | re.I)
    trabajo = re.sub(r"<code\b[^>]*>.*?</code>", _guardar, trabajo, flags=re.S | re.I)

    trabajo = re.sub(
        r"<p>\s*(?:<!--\s*(?:salto|pagebreak)\s*-->|:::\s*salto)\s*</p>",
        _SALTO_DIV,
        trabajo,
        flags=re.I,
    )
    trabajo = re.sub(
        r"<!--\s*(?:salto|pagebreak)\s*-->",
        _SALTO_DIV,
        trabajo,
        flags=re.I,
    )
    trabajo = re.sub(
        r"(?m)^\s*:::\s*salto\s*$",
        _SALTO_DIV,
        trabajo,
        flags=re.I,
    )

    def _restaurar(m):
        return protegidos[int(m.group(1))]

    return re.sub(r"\x00CLS_PRE_(\d+)\x00", _restaurar, trabajo)


def marcar_tablas_compactas(html_str, max_body_rows=12):
    """Añade clase tabla-compacta a <div class="tabla"> con <= max_body_rows filas de cuerpo."""
    def _rep(m):
        attr_rest = m.group(1)
        contenido = m.group(2)
        if "tabla-compacta" in attr_rest:
            return m.group(0)
        tbody_m = re.search(r"<tbody\b[^>]*>(.*?)</tbody>", contenido, flags=re.S | re.I)
        if tbody_m:
            num_filas = len(re.findall(r"<tr\b", tbody_m.group(1), flags=re.I))
        else:
            total_tr = len(re.findall(r"<tr\b", contenido, flags=re.I))
            has_thead = bool(re.search(r"<thead\b", contenido, flags=re.I))
            num_filas = max(0, total_tr - (1 if has_thead else 0))
        if num_filas <= max_body_rows:
            return f'<div class="tabla tabla-compacta"{attr_rest}>{contenido}</table></div>'
        return m.group(0)

    return re.sub(
        r'<div class="tabla"([^>]*)>(.*?)</table></div>',
        _rep,
        html_str,
        flags=re.S,
    )


def maquetar_html_impresion(body_html):
    """Aplica paginación editorial inteligente para A4 sin desperdiciar hojas ni romper arranques."""
    body_html = preprocesar_saltos_html(body_html)
    if "hoja-compacta" in body_html:
        return body_html

    body_html = marcar_tablas_compactas(body_html, max_body_rows=12)

    partes = re.split(r"(?=<h2\b[^>]*>)", body_html)
    if len(partes) <= 1:
        return body_html

    def peso_a4(html_seg):
        txt = _strip_html(html_seg)
        pre_lines = sum(
            m.group(1).count("\n") + 1
            for m in re.finditer(r"<pre\b[^>]*>(.*?)</pre>", html_seg, flags=re.S | re.I)
        )
        num_tablas = html_seg.count("<table")
        num_filas = html_seg.count("<tr")
        return len(txt) + pre_lines * 52 + num_filas * 60 + num_tablas * 85, pre_lines

    def es_compacto_a4(html_seg, max_peso=1950, max_pre_lines=20):
        if "salto-pagina-manual" in html_seg:
            return False
        if not _html_divs_balanceados(html_seg):
            return False
        peso, pre_lines = peso_a4(html_seg)
        return peso <= max_peso and pre_lines <= max_pre_lines

    _TOP_PATTERN = re.compile(
        r'(<h[2-6]\b[^>]*>.*?</h[2-6]>'
        r'|<p\b[^>]*>.*?</p>'
        r'|<pre\b[^>]*>.*?</pre>'
        r'|<div\b[^>]*class="salto-pagina-manual"[^>]*></div>'
        r'|<div\b[^>]*class="tabla[^"]*"[^>]*>.*?</table></div>'
        r'|<aside\b[^>]*>.*?</aside>'
        r'|<blockquote\b[^>]*>.*?</blockquote>'
        r'|<details\b[^>]*>.*?</details>'
        r'|<ul\b[^>]*>.*?</ul>'
        r'|<ol\b[^>]*>.*?</ol>'
        r'|<hr\s*/?>)',
        flags=re.S | re.I,
    )

    def envolver_arranque(html_seg, min_peso=450, max_peso=1450):
        """Une encabezado + primer bloque sustancial usando cortes por índice 100% sin pérdidas."""
        matches = list(_TOP_PATTERN.finditer(html_seg))
        if len(matches) <= 1:
            return html_seg
        # Debe empezar con el encabezado (solo espacios previos permitidos)
        if html_seg[: matches[0].start()].strip():
            return html_seg

        tomados = 1
        last_end = matches[0].end()
        tiene_bloque_fuerte = False

        for m in matches[1:]:
            # No saltar huecos con etiquetas no capturadas (p.ej. <div class="ampliacion-ext">)
            if html_seg[last_end : m.start()].strip():
                break
            el = m.group(0)
            if "salto-pagina-manual" in el:
                break
            candidato = html_seg[: m.end()]
            peso, pre_lines = peso_a4(candidato)
            if tomados > 1 and (peso > max_peso or pre_lines > 18):
                break
            last_end = m.end()
            tomados += 1
            if any(tag in el for tag in ("<pre", "<table", "<ul", "<ol", "<aside", "<details")):
                tiene_bloque_fuerte = True
            if tiene_bloque_fuerte and peso >= min_peso:
                break
            if tomados >= 3 and peso >= min_peso:
                break

        if tomados <= 1:
            return html_seg

        head_slice = html_seg[:last_end]
        tail_slice = html_seg[last_end:]
        if not _html_divs_balanceados(head_slice):
            return html_seg
        bloque_arr = f'<div class="arranque-inseparable">\n{head_slice}\n</div>'
        return f"{bloque_arr}\n{tail_slice}" if tail_slice.strip() else bloque_arr

    _SALTO_RE = re.compile(r'(?:\s*<div class="salto-pagina-manual"[^>]*></div>)+\s*$')

    def extraer_salto_final(html_seg):
        m = _SALTO_RE.search(html_seg)
        if not m:
            return html_seg, ""
        return html_seg[: m.start()], m.group(0).strip()

    def envolver_subtemas_h3(html_seg):
        subpartes = re.split(r"(?=<h3\b[^>]*>)", html_seg)
        if len(subpartes) <= 1:
            return html_seg
        if not all(_html_divs_balanceados(sp) for sp in subpartes):
            return envolver_arranque(html_seg)

        if (
            len(subpartes) >= 2
            and "salto-pagina-manual" not in subpartes[0]
            and peso_a4(subpartes[0])[0] < 650
            and not any(t in subpartes[0] for t in ("<table", "<pre", "<ul", "<ol", "<details"))
        ):
            subpartes = [subpartes[0] + "\n" + subpartes[1]] + subpartes[2:]

        res = []
        salto_pendiente = ""
        for sp in subpartes:
            sp_limpio, salto_trail = extraer_salto_final(sp)
            prefijo = f"{salto_pendiente}\n" if salto_pendiente else ""
            if es_compacto_a4(sp_limpio, max_peso=1650, max_pre_lines=16):
                res.append(f'{prefijo}<div class="subtema-h3-compacto">\n{sp_limpio}\n</div>')
            else:
                res.append(f'{prefijo}<div class="subtema-h3">\n{envolver_arranque(sp_limpio)}\n</div>')
            salto_pendiente = salto_trail
        if salto_pendiente:
            res.append(salto_pendiente)
        return "\n".join(res)

    intro, salto_h2_pend = extraer_salto_final(partes[0])
    intro_breve = (not salto_h2_pend) and peso_a4(intro)[0] < 900
    salida = [intro]
    h2_bloques = partes[1:]
    i = 0
    while i < len(h2_bloques):
        blk, salto_trail = extraer_salto_final(h2_bloques[i])
        prefijo = f"{salto_h2_pend}\n" if salto_h2_pend else ""
        m_tit = re.match(r"<h2\b[^>]*>(.*?)</h2>", blk, flags=re.S | re.I)
        tit_txt = _strip_html(m_tit.group(1)).lower() if m_tit else ""

        if ("antes de avanzar" in tit_txt or "comprobación rápida" in tit_txt) and i + 1 < len(h2_bloques):
            nxt, nxt_trail = extraer_salto_final(h2_bloques[i + 1])
            m_nxt = re.match(r"<h2\b[^>]*>(.*?)</h2>", nxt, flags=re.S | re.I)
            nxt_txt = _strip_html(m_nxt.group(1)).lower() if m_nxt else ""
            if ("referencias" in nxt_txt or "fuentes" in nxt_txt) and not salto_trail:
                combinado = blk + "\n" + nxt
                if es_compacto_a4(combinado, max_peso=2000, max_pre_lines=18):
                    salida.append(f'{prefijo}<div class="bloque-h2-unido">\n{combinado}\n</div>')
                    salto_h2_pend = nxt_trail
                    i += 2
                    continue

        # Si el H1/intro de sección es breve, no envolver el primer H2 en break-inside: avoid completo
        # para evitar que H1 quede solo en una página antes de que salte todo el bloque H2.
        forzar_flujo_primer_h2 = (i == 0 and intro_breve)
        if not forzar_flujo_primer_h2 and es_compacto_a4(blk, max_peso=1950, max_pre_lines=20):
            contenido = envolver_subtemas_h3(blk)
            salida.append(f'{prefijo}<div class="bloque-h2-compacto">\n{contenido}\n</div>')
        else:
            if "<h3" in blk:
                contenido = envolver_subtemas_h3(blk)
            else:
                contenido = envolver_arranque(blk)
            if _html_divs_balanceados(contenido):
                salida.append(f'{prefijo}<div class="bloque-h2-extenso">\n{contenido}\n</div>')
            else:
                salida.append(f"{prefijo}{contenido}")
        salto_h2_pend = salto_trail
        i += 1

    if salto_h2_pend:
        salida.append(salto_h2_pend)
    return "\n".join(salida)
