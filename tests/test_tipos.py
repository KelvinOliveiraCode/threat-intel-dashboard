"""Testes de coerencia de tipo na leitura dos dados.

Type-coherence tests for the data loaders.

O ponto deste arquivo e um bug real achado por auditoria independente:
``bool(dado.get("workaround", False))`` tratava a string ``"false"`` como
``True``, porque em Python qualquer string nao vazia e verdadeira. O efeito era
silencioso e ruim: o risco caia um ponto inteiro e o relatorio passava a
recomendar "aplicar workaround publicado" num CVE que nao tem workaround.

Numa ferramenta de seguranca, um "esta tudo bem" falso custa mais caro que um
erro barulhento.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intelhub.cruzamento import Exposicao
from intelhub.cvedb import _booleano, _normalizar, carregar_cves
from intelhub.inventario import Equipamento
from intelhub.priorizacao import calcular_risco

RAIZ = Path(__file__).resolve().parent.parent

CVE_BASE = {
    "id": "CVE-2026-0001",
    "description": "falha ficticia",
    "cvss": 8.1,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "affected_version": "1.0",
    "manufacturer": "Fabrikane",
    "model": "Modelo-X",
}


def _cve(**extra: object):
    """Monta um CVE a partir do dicionario base.

    Build a CVE from the base dict.
    """
    return _normalizar({**CVE_BASE, **extra})


def _equipamento() -> Equipamento:
    """Fabrica um equipamento de referencia.

    Build a reference device.
    """
    return Equipamento(
        fabricante="Fabrikane", modelo="Modelo-X", firmware="1.0",
        criticidade="alta", exposicao_red="interno",
    )


class TestBooleano:
    """A conversao do campo workaround."""

    @pytest.mark.parametrize("valor", [
        "false", "False", "FALSE", " false ", "nao", "no", "n", "0",
        "f", "off", "0.0", "",
    ])
    def test_falsos_em_texto(self, valor: str) -> None:
        assert _booleano(valor) is False

    @pytest.mark.parametrize("valor", [
        "true", "True", "sim", "yes", "y", "1", "t", "on", "1.0",
    ])
    def test_verdadeiros_em_texto(self, valor: str) -> None:
        assert _booleano(valor) is True

    @pytest.mark.parametrize("valor", [True, False])
    def test_booleano_nativo_passa(self, valor: bool) -> None:
        assert _booleano(valor) is valor

    @pytest.mark.parametrize("valor", [0, 1, 0.0, 1.0])
    def test_numerico_aceito(self, valor: object) -> None:
        assert _booleano(valor) is bool(valor)

    @pytest.mark.parametrize("valor", [2, -1, 0.5, 99])
    def test_numerico_fora_de_zero_e_um(self, valor: object) -> None:
        with pytest.raises(ValueError):
            _booleano(valor)

    @pytest.mark.parametrize("valor", ["talvez", "x", "?", "verdade", ""])
    def test_lixo_recusado(self, valor: str) -> None:
        # A string vazia e falso; o resto e lixo e precisa recusar.
        if valor == "":
            assert _booleano(valor) is False
        else:
            with pytest.raises(ValueError):
                _booleano(valor)

    def test_none_recusado(self) -> None:
        with pytest.raises(ValueError):
            _booleano(None)

    def test_lista_recusada(self) -> None:
        with pytest.raises(ValueError):
            _booleano([])

    def test_dict_recusado(self) -> None:
        with pytest.raises(ValueError):
            _booleano({})


class TestNormalizarWorkaround:
    """A regra dentro do carregador, que e onde o bug vivia."""

    def test_string_false_da_false(self) -> None:
        assert _cve(workaround="false").workaround is False

    def test_string_false_nao_da_true(self) -> None:
        # Este e o teste do achado. bool() daria True aqui.
        assert _cve(workaround="false").workaround is not True

    def test_booleano_padrao_e_false(self) -> None:
        assert _cve().workaround is False

    def test_string_true_da_true(self) -> None:
        assert _cve(workaround="sim").workaround is True

    def test_lixo_propaga_o_erro(self) -> None:
        with pytest.raises(ValueError):
            _cve(workaround="provavelmente")


class TestEfeitoNoRisco:
    """O impacto do bug na saida do relatorio."""

    def test_workaround_ausente_nao_desconta(self) -> None:
        item = calcular_risco(Exposicao(_equipamento(), _cve()))
        assert item.risco == pytest.approx(8.4)
        assert "workaround" not in item.justificativa

    def test_workaround_como_string_false_nao_desconta(self) -> None:
        # Com o bug, este dava 7.4 e recomendacao de aplicar workaround.
        item = calcular_risco(Exposicao(_equipamento(), _cve(workaround="false")))
        assert item.risco == pytest.approx(8.4)
        assert "workaround" not in item.justificativa

    def test_workaround_verdadeiro_desconta(self) -> None:
        item = calcular_risco(Exposicao(_equipamento(), _cve(workaround=True)))
        assert item.risco == pytest.approx(7.4)
        assert "workaround -1.0" in item.justificativa

    def test_workaround_como_nome_da_recomendacao(self) -> None:
        from intelhub.relatorio import _recomendacao

        sem = _recomendacao(calcular_risco(Exposicao(_equipamento(), _cve())))
        com = _recomendacao(
            calcular_risco(Exposicao(_equipamento(), _cve(workaround="false")))
        )
        assert sem == com
        assert "workaround" not in sem


class TestCarregarCves:
    """O caminho real, com arquivo em disco."""

    def test_arquivo_do_repositorio(self) -> None:
        cves = carregar_cves(RAIZ / "dados" / "cves-ficticias.json")
        assert len(cves) == 81
        assert all(isinstance(c.workaround, bool) for c in cves)

    def test_workaround_texto_no_arquivo(self, tmp_path: Path) -> None:
        # O erro real vem de base de terceiros e de planilha editada a mao.
        destino = tmp_path / "cves.json"
        destino.write_text(
            json.dumps([
                {**CVE_BASE, "id": "CVE-2026-0001", "workaround": "false"},
                {**CVE_BASE, "id": "CVE-2026-0002", "workaround": True},
            ]),
            encoding="utf-8",
        )
        cves = carregar_cves(destino)
        assert cves[0].workaround is False
        assert cves[1].workaround is True

    def test_workaround_lixo_no_arquivo(self, tmp_path: Path) -> None:
        destino = tmp_path / "cves.json"
        destino.write_text(
            json.dumps([{**CVE_BASE, "workaround": "nao sei"}]),
            encoding="utf-8",
        )
        with pytest.raises(ValueError):
            carregar_cves(destino)

    def test_arquivo_do_repositorio_usa_booleano_real(self) -> None:
        bruto = json.loads(
            (RAIZ / "dados" / "cves-ficticias.json").read_text(encoding="utf-8")
        )
        assert {type(c["workaround"]).__name__ for c in bruto} == {"bool"}


class TestCoerenciaComInventario:
    """O inventario ja validava; o CVE nao. Agora os dois validam."""

    def test_criticidade_invalida_e_recusada(self) -> None:
        from intelhub.inventario import _normalizar as normalizar_eq

        with pytest.raises(ValueError):
            normalizar_eq({
                "fabricante": "F", "modelo": "M", "firmware": "1.0",
                "criticidade": "urgentissima", "exposicao_red": "interno",
            })

    def test_cvss_fora_do_range(self) -> None:
        with pytest.raises(ValueError):
            _cve(cvss=10.5)

    def test_id_de_ano_errado(self) -> None:
        with pytest.raises(ValueError):
            _cve(id="CVE-2025-0001")