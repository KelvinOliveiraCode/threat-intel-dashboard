"""Prova de aceite do intelhub.

Acceptance proof for intelhub.

O criterio de aceite da especificacao tem tres partes:

1. o cruzamento encontra os 6 equipamentos plantados como vulneraveis;
2. o ranking sai ordenado por risco;
3. a justificativa do numero aparece no relatorio.

Este script verifica as tres e mais duas coisas que o criterio nao pede, mas que
sao o que torna o numero confiavel:

- existe pelo menos um equipamento **sem** exposicao, para provar que o
  cruzamento filtra em vez de casar com tudo;
- as CVEs sao todas ficticias, no formato ``CVE-2026-XXXXX``, e nenhuma
  entrada do inventario e exposta por uma CVE de outro fabricante.

Roda fora do pytest de proposito.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Permite executar o script direto do checkout, sem instalar o pacote.
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from intelhub.cruzamento import cruzar  # noqa: E402
from intelhub.cvedb import carregar_cves  # noqa: E402
from intelhub.inventario import carregar_inventario  # noqa: E402
from intelhub.priorizacao import rankear  # noqa: E402

INVENTARIO = RAIZ / "dados" / "inventario-equipamentos.json"
CVES = RAIZ / "dados" / "cves-ficticias.json"

#: Minimo de equipamentos expostos que a especificacao exige.
MINIMO_EXPOSTOS = 6

#: Minimo de CVEs na base.
MINIMO_CVES = 60


def main() -> int:
    """Verifica o criterio de aceite.

    Verify the acceptance criterion.
    """
    falhas: list[str] = []

    inventario = carregar_inventario(INVENTARIO)
    cves = carregar_cves(CVES)

    print(f"inventario: {INVENTARIO.name}  {len(inventario)} equipamentos")
    print(f"base de CVEs: {CVES.name}  {len(cves)} CVEs")

    if len(cves) < MINIMO_CVES:
        falhas.append(
            f"a base tem {len(cves)} CVEs, a especificacao exige "
            f"ao menos {MINIMO_CVES}"
        )

    # Nenhuma CVE pode ser real: o formato e conferido na carga, mas o script
    # deixa isso explicito.
    for cve in cves:
        if not cve.id.startswith("CVE-2026-"):
            falhas.append(f"{cve.id} fora do formato ficticio")
            break

    exposicoes = cruzar(inventario, cves)
    expostos = {
        (e.equipamento.fabricante, e.equipamento.modelo, e.equipamento.firmware)
        for e in exposicoes
    }
    todos = {
        (e.fabricante, e.modelo, e.firmware) for e in inventario
    }
    limpos = todos - expostos

    print(f"\nexposicoes: {len(exposicoes)}")
    print(f"equipamentos expostos: {len(expostos)}")
    print(f"equipamentos limpos: {len(limpos)}")

    if len(expostos) < MINIMO_EXPOSTOS:
        falhas.append(
            f"o cruzamento encontrou {len(expostos)} equipamentos expostos, "
            f"a especificacao exige ao menos {MINIMO_EXPOSTOS}"
        )
    if not limpos:
        falhas.append(
            "nenhum equipamento sem exposicao: o cruzamento casa com tudo, "
            "o que nao prova que o filtro funciona"
        )

    for fabricante, modelo, firmware in sorted(limpos):
        print(f"  limpo: {fabricante} {modelo} fw={firmware}")

    # Toda exposicao tem que casar fabricante e modelo de verdade.
    for exposicao in exposicoes:
        if (
            exposicao.cve.manufacturer.lower() != exposicao.equipamento.fabricante.lower()
            or exposicao.cve.model.lower() != exposicao.equipamento.modelo.lower()
        ):
            falhas.append(
                f"{exposicao.cve.id} casa com {exposicao.equipamento.fabricante} "
                f"{exposicao.equipamento.modelo}, que nao e o alvo declarado"
            )
            break

    ranking = rankear(exposicoes)
    print(f"\nranking: {len(ranking)} itens")

    if not ranking:
        falhas.append("o ranking saiu vazio")
    else:
        riscos = [i.risco for i in ranking]
        if riscos != sorted(riscos, reverse=True):
            falhas.append("o ranking nao esta ordenado do maior para o menor")
        print(f"  primeiro: {ranking[0].exposicao.cve.id} "
              f"{ranking[0].exposicao.equipamento.modelo} risco={ranking[0].risco}")
        print(f"  ultimo:  {ranking[-1].exposicao.cve.id} "
              f"{ranking[-1].exposicao.equipamento.modelo} risco={ranking[-1].risco}")

        # Justificativa visivel: o numero sozinho nao serve para decisao.
        sem_justificativa = [i for i in ranking if not i.justificativa]
        if sem_justificativa:
            falhas.append(
                f"{len(sem_justificativa)} item(ns) do ranking sem justificativa"
            )

        # O ranking tem de ter variety: se tudo da a mesma nota, ele nao
        # distingue nada.
        if len(set(riscos)) < 2:
            falhas.append("todos os itens do ranking tem a mesma nota")

        # Nenhum item pode ter combinacao invalida de CVSS.
        for item in ranking:
            if not (0.0 <= item.risco <= 10.0):
                falhas.append(
                    f"{item.exposicao.cve.id}: risco {item.risco} fora de 0 a 10"
                )
                break

    print(f"\nCVEs por fabricante:")
    por_fabricante: dict[str, int] = {}
    for cve in cves:
        por_fabricante[cve.manufacturer] = por_fabricante.get(cve.manufacturer, 0) + 1
    for nome, quantos in sorted(por_fabricante.items()):
        print(f"  {nome:<12} {quantos}")

    if falhas:
        print("\nFALHOU:")
        for falha in falhas:
            print(f"  - {falha}")
        return 1

    print(
        f"\nok: {len(expostos)} equipamentos expostos (minimo {MINIMO_EXPOSTOS}), "
        f"{len(limpos)} limpo(s) provando que o filtro funciona, ranking "
        "ordenado com justificativa em cada item"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())