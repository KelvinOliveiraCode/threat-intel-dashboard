"""Base local de CVEs ficticias.

Local CVE database holding synthetic vulnerabilities only. Every id follows
the ``CVE-2026-XXXXX`` shape so it is obvious at a glance that no real scanner
data is mixed in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CVE:
    """Uma vulnerabilidade sintetica.

    A synthetic vulnerability record.

    Attributes:
        id: Identificador no formato ``CVE-2026-XXXXX``.
        description: Descrita em PT-BR e EN.
        cvss: Pontuacao CVSS (0.0 - 10.0).
        vector: Vetor de ataque CVSS (ex: ``CVSS:3.1/AV:N/AC:L/...``).
        affected_version: Faixa de versao afetada (ex: ``9.0.0 - 9.2.4``).
        manufacturer: Fabricante afetado.
        model: Modelo afetado.
        workaround: ``true`` se ha workaround publicado.
    """

    id: str
    description: str
    cvss: float
    vector: str
    affected_version: str
    manufacturer: str
    model: str
    workaround: bool

    def __post_init__(self) -> None:
        if not self.id.startswith("CVE-2026-"):
            raise ValueError(f"id deve comecar com CVE-2026-: {self.id!r}")
        if not (0.0 <= float(self.cvss) <= 10.0):
            raise ValueError(f"cvss fora do range 0.0-10.0: {self.cvss}")
        if not self.affected_version:
            raise ValueError("affected_version e obrigatorio")


def _normalizar(dado: dict[str, Any]) -> CVE:
    return CVE(
        id=str(dado.get("id", "")).strip(),
        description=str(dado.get("description", "")).strip(),
        cvss=float(dado.get("cvss", 0.0)),
        vector=str(dado.get("vector", "")).strip(),
        affected_version=str(dado.get("affected_version", "")).strip(),
        manufacturer=str(dado.get("manufacturer", "")).strip(),
        model=str(dado.get("model", "")).strip(),
        workaround=bool(dado.get("workaround", False)),
    )


def carregar_cves(caminho: str | Path) -> list[CVE]:
    """Le um arquivo JSON de CVEs e retorna a lista.

    Read a CVE JSON file and return the list.

    Raises:
        ValueError: Se o arquivo nao for uma lista ou tiver items invalidos.
        OSError: Se o arquivo nao existir.
    """
    with open(caminho, "r", encoding="utf-8") as fh:
        dados = json.load(fh)
    if not isinstance(dados, list):
        raise ValueError(f"{caminho}: esperado uma lista no topo / expected a list at the top")
    return [_normalizar(item) for item in dados]


class VersaoInvalida(ValueError):
    """A versao nao e numerica com pontos.

    A version string is not a dotted numeric version.
    """


def _tuple(ver: str) -> tuple[int, ...]:
    """Converte ``"7.2.1"`` em ``(7, 2, 1)`` para comparacao.

    Convert ``"7.2.1"`` into ``(7, 2, 1)`` for comparison.

    Uma parte que nao for numero levanta :class:`VersaoInvalida`. A versao
    anterior trocava qualquer coisa nao numerica por zero, entao
    ``"1.2.beta"`` virava ``(1, 2, 0)`` e era tratada como ``1.2.0``. Num
    relatorio de exposicao, aceitar uma versao inventada como se fosse outra e
    o tipo de erro que faz um equipamento vulneravel sumir do ranking.

    Args:
        ver: Versao em texto, como ``"7.2.1"``.

    Returns:
        Tupla de inteiros.

    Raises:
        VersaoInvalida: Se alguma parte nao for inteira.
    """
    partes = ver.strip().split(".")
    saida: list[int] = []
    for parte in partes:
        if not parte.isdigit():
            raise VersaoInvalida(
                f"versao nao numerica: {ver!r} (parte {parte!r})"
            )
        saida.append(int(parte))
    if not saida:
        raise VersaoInvalida(f"versao vazia: {ver!r}")
    return tuple(saida)


def _alinhado(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Completa com zeros as duas tuplas ate terem o mesmo tamanho.

    Pad both tuples with zeros until they have the same length.

    Sem isso, ``(9, 2, 0)`` e ``(9, 2)`` sao tuplas de tamanhos diferentes, e em
    Python ``(9, 2, 0) > (9, 2)``: o prefixo igual decide pelo tamanho. Isso faz
    ``9.2.0`` ficar FORA de uma faixa que termina em ``9.2``, e ``9.2.0`` ser
    considerado diferente de ``9.2``. Num relatorio de exposicao, a consequencia
    e um equipamento vulnavel nao aparecer no ranking.

    Args:
        a: Primeira tupla.
        b: Segunda tupla.

    Returns:
        As duas tuplas com o mesmo tamanho.
    """
    tamanho = max(len(a), len(b))
    return (
        a + (0,) * (tamanho - len(a)),
        b + (0,) * (tamanho - len(b)),
    )


def _comparar(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compara duas versoes alinhadas.

    Compare two aligned versions.

    Args:
        a: Primeira versao.
        b: Segunda versao.

    Returns:
        Negativo, zero ou positivo, como uma funcao de comparacao.
    """
    a_cheio, b_cheio = _alinhado(a, b)
    if a_cheio < b_cheio:
        return -1
    if a_cheio > b_cheio:
        return 1
    return 0


def versao_no_alcance(versao: str, alcance: str) -> bool:
    """Verifica se ``versao`` pertence a ``alcance``.

    Check whether ``version`` falls inside ``range``.

    Formas aceitas, todas com versao numerica com pontos:

    - ``"9.0.0 - 9.2.4"``: intervalo fechado nos dois lados.
    - ``">=9.0.0"``, ``"<9.2.4"``, ``">9.0.0"``, ``"<=9.2.4"``, ``"==9.1.0"``.
    - ``"9.2.1"``: igualdade exata.

    Args:
        versao: Versao do equipamento.
        alcance: Faixa afetada pela CVE.

    Returns:
        ``True`` se a versao cai na faixa.

    Raises:
        VersaoInvalida: Se a versao ou a faixa nao forem numericas.
        ValueError: Se o intervalo nao tiver duas pontas.
    """
    alvo = _tuple(versao)
    alcance = alcance.strip()

    if "-" in alcance:
        partes = [p.strip() for p in alcance.split("-")]
        if len(partes) != 2:
            raise ValueError(f"alcance invalido: {alcance!r}")
        inicio = _tuple(partes[0])
        fim = _tuple(partes[1])
        return _comparar(alvo, inicio) >= 0 and _comparar(alvo, fim) <= 0

    for op in (">=", "<=", "==", ">", "<"):
        if alcance.startswith(op):
            referencia = _tuple(alcance[len(op):].strip())
            comparacao = _comparar(alvo, referencia)
            if op == ">=":
                return comparacao >= 0
            if op == "<=":
                return comparacao <= 0
            if op == "==":
                return comparacao == 0
            if op == ">":
                return comparacao > 0
            return comparacao < 0

    return _comparar(alvo, _tuple(alcance)) == 0