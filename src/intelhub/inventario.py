"""Leitura do inventario de equipamentos.

Equipment inventory loading. Supports a JSON file whose top level is a
list of equipment objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Equipamento:
    """Um equipamento da rede.

    A network equipment asset.

    Attributes:
        fabricante: Nome do fabricante (case-insensitive na comparacao).
        modelo: Modelo do equipamento.
        firmware: Versao de firmware instalada.
        criticidade: ``baixa``, ``media``, ``alta`` ou ``critica``.
        exposicao_red: ``publico`` (exposto na internet) ou ``interno``.
    """

    fabricante: str
    modelo: str
    firmware: str
    criticidade: str
    exposicao_red: str

    def __post_init__(self) -> None:
        if not self.fabricante or not self.modelo:
            raise ValueError("fabricante e modelo sao obrigatorios")
        if not self.firmware:
            raise ValueError("firmware e obrigatorio")
        if self.criticidade not in ("baixa", "media", "alta", "critica"):
            raise ValueError(
                f"criticidade invalida: {self.criticidade!r} (use baixa/media/alta/critica)"
            )
        if self.exposicao_red not in ("publico", "interno"):
            raise ValueError(
                f"exposicao_red invalida: {self.exposicao_red!r} (use publico/interno)"
            )


def _normalizar(dado: dict[str, Any]) -> Equipamento:
    return Equipamento(
        fabricante=str(dado.get("fabricante", "")).strip(),
        modelo=str(dado.get("modelo", "")).strip(),
        firmware=str(dado.get("firmware", "")).strip(),
        criticidade=str(dado.get("criticidade", "media")).strip().lower(),
        exposicao_red=str(dado.get("exposicao_red", "interno")).strip().lower(),
    )


def carregar_inventario(caminho: str | Path) -> list[Equipamento]:
    """Le um arquivo JSON de inventario e retorna a lista de equipamentos.

    Read an inventory JSON file and return the equipment list.

    Args:
        caminho: Caminho para o ``.json``.

    Returns:
        Lista de :class:`Equipamento`.

    Raises:
        ValueError: Se o arquivo nao for uma lista ou tiver items invalidos.
        OSError: Se o arquivo nao existir.
    """
    with open(caminho, "r", encoding="utf-8") as fh:
        dados = json.load(fh)
    if not isinstance(dados, list):
        raise ValueError(f"{caminho}: esperado uma lista no topo / expected a list at the top")
    return [_normalizar(item) for item in dados]