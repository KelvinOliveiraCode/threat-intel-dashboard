"""CLI do intelhub - dashboard de threat intel.

CLI entry point for intelhub. Cross-references an equipment inventory
against a local CVE database and writes a prioritized HTML exposure
report.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .cruzamento import cruzar
from .priorizacao import rankear
from .relatorio import gerar_relatorio_html
from .cvedb import carregar_cves
from .inventario import carregar_inventario


def _cmd_cruzar(args: argparse.Namespace) -> int:
    """Cruza inventario com CVEs e gera relatorio.

    Cross-reference the inventory with CVEs and write the report.
    """
    inventario = carregar_inventario(args.inventario)
    cves = carregar_cves(args.cves)
    exposicoes = cruzar(inventario, cves)
    ranking = rankear(exposicoes)

    caminho = Path(args.saida)
    caminho.parent.mkdir(parents=True, exist_ok=True)

    gerado_em = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    html = gerar_relatorio_html(ranking, caminho_gerado_em=gerado_em)
    caminho.write_text(html, encoding="utf-8")

    print(
        f"Equipamentos inventariados: {len(inventario)}\n"
        f"CVEs na base: {len(cves)}\n"
        f"Exposicoes encontradas: {len(exposicoes)}\n"
        f"Relatorio gravado em: {caminho}"
    )
    return 0


def construir_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos.

    Build the argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="intelhub",
        description=(
            "Cruza um inventario de equipamentos com uma base local de CVEs "
            "e gera um relatorio de exposicao priorizado. "
            "Cross-references an equipment inventory against a local CVE "
            "database and produces a prioritized exposure report."
        ),
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    p_cruzar = sub.add_parser(
        "cruzar",
        help="Cruza inventario com CVEs e gera relatorio HTML.",
    )
    p_cruzar.add_argument("inventario", help="Caminho do JSON do inventario.")
    p_cruzar.add_argument("cves", help="Caminho do JSON de CVEs.")
    p_cruzar.add_argument("--saida", required=True, help="Caminho do HTML de saida.")
    p_cruzar.set_defaults(func=_cmd_cruzar)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada da CLI.

    CLI entry point.
    """
    parser = construir_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"Erro / error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())