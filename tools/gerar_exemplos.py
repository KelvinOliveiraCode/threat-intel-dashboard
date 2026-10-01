#!/usr/bin/env python
"""Regera os exemplos versionados de forma deterministica.

Regenerate the committed examples deterministically.

O relatorio de exemplo nao pode ser gerado pela CLI, porque a CLI carimba a
hora atual no cabecalho e o CI compara o arquivo recem-gerado com o que esta
no repositorio. Com data de execucao o `git diff` acusaria diferenca em toda
build. Aqui a data e fixa, o mesmo ranking sai sempre, e o exemplo continua
sendo o mesmo relatorio que o comando do README produz - so que sem o carimbo
de agora.
"""

from __future__ import annotations

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from intelhub.cruzamento import cruzar  # noqa: E402
from intelhub.cvedb import carregar_cves  # noqa: E402
from intelhub.inventario import carregar_inventario  # noqa: E402
from intelhub.priorizacao import rankear  # noqa: E402
from intelhub.relatorio import gerar_relatorio_html  # noqa: E402

# Data fixa. Um exemplo versionado precisa contar a mesma historia hoje e na
# proxima execucao da suite.
DATA_FIXA = "2026-01-15 09:00"


def main() -> int:
    """Regera o relatorio de exemplo.

    Regenerate the example report.

    Returns:
        0 quando o exemplo foi escrito.
    """
    inventario = carregar_inventario(RAIZ / "dados" / "inventario-equipamentos.json")
    cves = carregar_cves(RAIZ / "dados" / "cves-ficticias.json")
    ranking = rankear(cruzar(inventario, cves))

    destino = RAIZ / "exemplos" / "relatorio-exposicao.html"
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(
        gerar_relatorio_html(ranking, caminho_gerado_em=DATA_FIXA),
        encoding="utf-8",
    )

    expostos = {
        (i.exposicao.equipamento.fabricante, i.exposicao.equipamento.modelo)
        for i in ranking
    }
    print(
        f"exemplo regerado: {destino.relative_to(RAIZ)}\n"
        f"  {len(cves)} CVEs, {len(ranking)} exposicoes, "
        f"{len(expostos)} ativos expostos"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
