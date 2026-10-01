"""Geracao de relatorio HTML.

Render a prioritized exposure report as a self-contained HTML document.
The file carries no absolute paths and can be opened directly in a
browser.
"""

from __future__ import annotations

from typing import Iterable

from .priorizacao import ItemRisco


def _esc(texto: str) -> str:
    return (
        texto.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _classe_risco(risco: float) -> str:
    if risco >= 7.0:
        return "critico"
    if risco >= 4.0:
        return "alto"
    if risco >= 2.0:
        return "medio"
    return "baixo"


def _recomendacao(item: ItemRisco) -> str:
    cve = item.exposicao.cve
    eq = item.exposicao.equipamento
    if cve.workaround:
        return (
            f"Aplicar workaround publicado e agendar atualizacao de firmware "
            f"do {eq.fabricante} {eq.modelo}."
        )
    return (
        f"Atualizar firmware do {eq.fabricante} {eq.modelo} para versao "
        f"fora do alcance {cve.affected_version}."
    )


def _linhas(
    itens: Iterable[ItemRisco],
) -> str:
    partes: list[str] = []
    for item in itens:
        eq = item.exposicao.equipamento
        cve = item.exposicao.cve
        partes.append(
            f"<tr class=\"{_classe_risco(item.risco)}\">"
            f"<td>{_esc(cve.id)}</td>"
            f"<td>{_esc(eq.fabricante)}</td>"
            f"<td>{_esc(eq.modelo)}</td>"
            f"<td>{_esc(eq.firmware)}</td>"
            f"<td>{_esc(eq.criticidade)}</td>"
            f"<td>{_esc(eq.exposicao_red)}</td>"
            f"<td>{item.risco:.2f}</td>"
            f"<td>{_esc(item.justificativa)}</td>"
            f"<td>{_esc(_recomendacao(item))}</td>"
            "</tr>"
        )
    return "\n".join(partes)


def _agrupar(itens: list[ItemRisco]) -> str:
    """Render one section per equipment, in risk-descending order.

    Render one section per equipment, in risk-descending order.
    """
    por_equipamento: dict[tuple[str, str], list[ItemRisco]] = {}
    for item in itens:
        eq = item.exposicao.equipamento
        por_equipamento.setdefault((eq.fabricante, eq.modelo), []).append(item)

    secoes: list[str] = []
    for (fabricante, modelo), items in sorted(
        por_equipamento.items(), key=lambda kv: kv[1][0].risco, reverse=True
    ):
        items_ordenados = sorted(items, key=lambda i: i.risco, reverse=True)
        linhas = _linhas(items_ordenados)
        secoes.append(
            "<section class=\"asset\">"
            f"<h2>{_esc(fabricante)} {_esc(modelo)}</h2>"
            "<table>"
            "<thead><tr>"
            "<th>CVE</th><th>Fabricante</th><th>Modelo</th>"
            "<th>Firmware</th><th>Criticidade</th><th>Exposicao</th>"
            "<th>Risco</th><th>Justificativa</th><th>Recomendacao</th>"
            "</tr></thead>"
            f"<tbody>{linhas}</tbody>"
            "</table>"
            "</section>"
        )
    return "\n".join(secoes)


ESTILO = """
:root {
  color-scheme: light;
  --tinta: #111111;
  --papel: #ffffff;
  --cinza: #6b6b6b;
  --linha: #e2e2e2;
  --vermelho: #c62828;
  --azul: #1565c0;
}
* { box-sizing: border-box; }
body {
  font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  font-weight: 300;
  line-height: 1.6;
  margin: 0;
  padding: 48px 24px;
  background: var(--papel);
  color: var(--tinta);
}
main { max-width: 1120px; margin: 0 auto; }
h1 {
  font-size: 28px;
  font-weight: 200;
  letter-spacing: -0.01em;
  margin: 0 0 4px;
}
.subtitle {
  color: var(--cinza);
  font-size: 13px;
  margin: 0 0 36px;
}
.summary {
  border-top: 1px solid var(--linha);
  border-bottom: 1px solid var(--linha);
  padding: 20px 0;
  margin-bottom: 40px;
  display: flex;
  gap: 40px;
  font-size: 13px;
}
.summary strong {
  display: block;
  font-size: 24px;
  font-weight: 300;
}
.summary span {
  display: block;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 10px;
  color: var(--cinza);
}
table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
th, td {
  border-bottom: 1px solid var(--linha);
  padding: 10px 12px;
  text-align: left;
  vertical-align: top;
  font-size: 13px;
}
th {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--cinza);
  font-weight: 400;
  border-bottom: 1px solid var(--tinta);
}
section.asset { margin-bottom: 48px; }
section.asset h2 {
  font-size: 15px;
  font-weight: 400;
  margin: 0 0 8px;
}
/* A severidade marca a linha pela borda esquerda, nao por fundo colorido.
   Um relatorio de 73 linhas precisa que a escala se leia sem faixas de cor
   saturada competindo com o texto. */
tr.critico td:first-child { border-left: 2px solid var(--vermelho); }
tr.alto td:first-child { border-left: 2px solid var(--azul); }
tr.medio td:first-child { border-left: 2px solid var(--cinza); }
tr.baixo td:first-child { border-left: 2px solid var(--linha); }
td:nth-child(7) { font-family: Consolas, 'Courier New', monospace; }
td:nth-child(8) { color: var(--cinza); font-size: 12px; }
"""


def gerar_relatorio_html(
    itens: list[ItemRisco],
    caminho_gerado_em: str | None = None,
) -> str:
    """Gera o HTML do relatorio.

    Generate the report HTML.

    Args:
        itens: Itens do ranking de risco.
        caminho_gerado_em: Texto opcional mostrado no cabecalho.

    Returns:
        O documento HTML como string.
    """
    total = len(itens)
    maior = max((i.risco for i in itens), default=0.0)
    criticos = sum(
        1 for i in itens if _classe_risco(i.risco) in ("critico", "alto")
    )
    distintas = len({i.exposicao.cve.id for i in itens})
    corpos = _agrupar(itens)

    resumo = (
        f"<div><span>Itens avaliados</span><strong>{total}</strong></div>"
        f"<div><span>Criticos ou altos</span><strong>{criticos}</strong></div>"
        f"<div><span>Maior risco</span><strong>{maior:.2f}</strong></div>"
        f"<div><span>CVEs distintas</span><strong>{distintas}</strong></div>"
    )
    marca = f"Gerado em {caminho_gerado_em}." if caminho_gerado_em else ""

    return (
        "<!DOCTYPE html>\n<html lang=\"pt-BR\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>Relatorio de Exposicao - Threat Intel</title>\n"
        f"<style>{ESTILO}</style>\n"
        "</head>\n<body>\n<main>\n"
        "<h1>Relatorio de Exposicao de Ativos</h1>\n"
        "<p class=\"subtitle\">Cruzamento de inventario com base local de "
        f"CVEs ficticias. {marca}</p>\n"
        f"<div class=\"summary\">{resumo}</div>\n"
        + corpos
        + "\n</main>\n</body>\n</html>\n"
    )