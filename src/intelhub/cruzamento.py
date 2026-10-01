"""Cruzamento de inventario com CVEs.

Match equipment against CVEs by manufacturer, model and affected-version
range. The result is one exposure record per (equipment, CVE) pair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .cvedb import CVE, versao_no_alcance
from .inventario import Equipamento


@dataclass(frozen=True)
class Exposicao:
    """Um par (equipamento, CVE) que se encaixa.

    An (equipment, CVE) match.

    Attributes:
        equipamento: O :class:`Equipamento` afetado.
        cve: A :class:`CVE` correspondente.
    """

    equipamento: Equipamento
    cve: CVE

    def __post_init__(self) -> None:
        if not versao_no_alcance(self.equipamento.firmware, self.cve.affected_version):
            raise ValueError(
                f"{self.equipamento.firmware} nao esta no alcance "
                f"{self.cve.affected_version!r}"
            )


def _mesmo(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


def cruzar(
    inventario: Iterable[Equipamento],
    cves: Iterable[CVE],
) -> list[Exposicao]:
    """Cruza inventario com CVEs.

    Cross-reference the inventory against the CVE list.

    Args:
        inventario: Lista de equipamentos.
        cves: Lista de CVEs.

    Returns:
        Lista de :class:`Exposicao` cujos fabricantes, modelos e firmwares
        se encaixam na faixa de versao afetada da CVE.
    """
    lista_cves = list(cves)
    saida: list[Exposicao] = []
    for eq in inventario:
        for cve in lista_cves:
            if not _mesmo(eq.fabricante, cve.manufacturer):
                continue
            if not _mesmo(eq.modelo, cve.model):
                continue
            if not versao_no_alcance(eq.firmware, cve.affected_version):
                continue
            saida.append(Exposicao(equipamento=eq, cve=cve))
    return saida