"""intelhub - cruzamento de inventario de equipamentos com base local de CVEs.

Cruza um inventario local de equipamentos com uma base local de CVEs
ficticias e gera um relatorio de exposicao priorizado. Funciona offline,
so com a biblioteca padrao do Python.

Threat-intel dashboard: cross-references an equipment inventory against a
local CVE database and produces a prioritized exposure report. Runs offline
using only the Python standard library.
"""

from .inventario import Equipamento, carregar_inventario
from .cvedb import CVE, carregar_cves, versao_no_alcance
from .cruzamento import Exposicao, cruzar
from .priorizacao import calcular_risco, rankear
from .relatorio import gerar_relatorio_html

__all__ = [
    "Equipamento",
    "carregar_inventario",
    "CVE",
    "carregar_cves",
    "versao_no_alcance",
    "Exposicao",
    "cruzar",
    "calcular_risco",
    "rankear",
    "gerar_relatorio_html",
]

__version__ = "1.0.0"