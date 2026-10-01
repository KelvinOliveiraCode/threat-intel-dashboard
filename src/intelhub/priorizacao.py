"""Priorizacao de risco.

CVSS sozinho nao decide prioridade. Este modulo combina pontuacao de
vulnerabilidade com contexto operacional - exposicao de rede, criticidade
do ativo e existencia de workaround - e devolve um ranking.

Risk prioritization. CVSS alone does not decide priority. This module
combines the vulnerability score with operational context - network
exposure, asset criticality and whether a published workaround exists -
and returns a risk-ranked list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .cruzamento import Exposicao


# Multiplicador de exposicao de rede. Um equipamento exposto na internet
# pinta muito mais do que um que fica so no VLAN de gerencia.
_EXPOSICAO = {"publico": 1.1, "interno": 1.0}

# Acrescimo de criticidade do ativo. Um switch de core vale mais que um
# ponto de acesso de escritorio.
_CRITICIDADE = {"critica": 0.5, "alta": 0.3, "media": 0.1, "baixa": 0.0}

# Reducao quando o fabricante ja publicou workaround. Isso nao elimina o
# risco, mas tira o item do topo do ranking.
_WORKAROUND = 1.0


@dataclass(frozen=True)
class ItemRisco:
    """Um item do ranking de risco.

    A risk-ranking item.

    Attributes:
        exposicao: A :class:`Exposicao` que gerou este item.
        risco: Pontuacao final de risco (0.0 - 10.0).
        justificativa: Texto curto que explica o numero.
    """

    exposicao: Exposicao
    risco: float
    justificativa: str


def _arredondar(valor: float) -> float:
    return round(valor, 2)


def calcular_risco(exposicao: Exposicao) -> ItemRisco:
    """Calcula o risco de uma unica exposicao.

    Compute the risk score for a single exposure.

    The formula is intentionally simple and auditable:

    - ``base = CVSS`` (0.0 - 10.0)
    - ``base * fator_exposicao`` - publico multiplica, interno nao
    - ``+ acrescimo_criticidade`` - ativos criticos empurram para cima
    - ``- 1.0`` se houver workaround publicado (nunca abaixo de 0.0)
    - resultado limitado a 0.0 - 10.0
    """
    cve = exposicao.cve
    eq = exposicao.equipamento

    base = float(cve.cvss)
    fator = _EXPOSICAO.get(eq.exposicao_red, 1.0)
    criticidade = _CRITICIDADE.get(eq.criticidade, 0.0)

    risco = (base * fator) + criticidade
    workaround = bool(cve.workaround)
    if workaround:
        risco -= _WORKAROUND

    risco = max(0.0, min(10.0, risco))
    risco = _arredondar(risco)

    partes = [f"CVSS {base:.1f}"]
    if fator != 1.0:
        partes.append(f"exposicao {fator:g}x")
    if criticidade:
        partes.append(f"criticidade +{criticidade:g}")
    if workaround:
        partes.append("workaround -1.0")

    return ItemRisco(
        exposicao=exposicao,
        risco=risco,
        justificativa="; ".join(partes),
    )


def rankear(exposicoes: Iterable[Exposicao]) -> list[ItemRisco]:
    """Gera o ranking de risco, do maior para o menor.

    Produce the risk ranking, highest score first. Ties are broken by
    CVSS and then by CVE id so the order is deterministic.
    """
    itens = [calcular_risco(e) for e in exposicoes]
    return sorted(
        itens,
        key=lambda i: (i.risco, i.exposicao.cve.cvss, i.exposicao.cve.id),
        reverse=True,
    )