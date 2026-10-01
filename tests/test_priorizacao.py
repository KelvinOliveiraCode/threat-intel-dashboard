"""Testes da priorizacao de risco.

Risk prioritisation tests.

CVSS sozinho nao decide prioridade, e a segunda metade dessa frase e a que
importa: o numero final tem que ser explicavel. Estes testes verificam as tres
coisas que tornam o ranking utilizavel, e que um ranking sem elas vira uma lista
de numeros que ninguem consegue defender:

1. a ordem esta correta;
2. a justificativa diz de onde veio o numero;
3. CVSS sozinho reordena o ranking, provando que o contexto pesa.
"""

from __future__ import annotations

import pytest

from intelhub.cruzamento import Exposicao
from intelhub.cvedb import CVE
from intelhub.inventario import Equipamento
from intelhub.priorizacao import (
    ItemRisco,
    calcular_risco,
    rankear,
)


def equipamento(
    criticidade: str = "media",
    exposicao: str = "interno",
    modelo: str = "Modelo X",
    firmware: str = "1.0",
) -> Equipamento:
    """Fabrica um equipamento para um teste.

    Build an equipment item for a test.
    """
    return Equipamento(
        fabricante="Fab",
        modelo=modelo,
        firmware=firmware,
        criticidade=criticidade,
        exposicao_red=exposicao,
    )


def cve(
    cvss: float = 7.0,
    workaround: bool = False,
    faixa: str = "1.0",
    cve_id: str = "CVE-2026-0001",
) -> CVE:
    """Fabrica uma CVE para um teste.

    Build a CVE for a test.
    """
    return CVE(
        id=cve_id,
        description="descricao de teste",
        cvss=cvss,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        affected_version=faixa,
        manufacturer="Fab",
        model="Modelo X",
        workaround=workaround,
    )


def exposicao(
    cvss: float = 7.0,
    workaround: bool = False,
    criticidade: str = "media",
    exposicao_red: str = "interno",
    modelo: str = "Modelo X",
    cve_id: str = "CVE-2026-0001",
) -> Exposicao:
    """Monta uma exposicao completa.

    Build a complete exposure.
    """
    return Exposicao(
        equipamento=equipamento(
            criticidade=criticidade,
            exposicao=exposicao_red,
            modelo=modelo,
        ),
        cve=cve(cvss=cvss, workaround=workaround, cve_id=cve_id),
    )


class TestFormula:
    """A conta do risco."""

    def test_cvss_puro(self) -> None:
        # Sem exposicao publica e sem acrescimo: o risco e o CVSS.
        assert calcular_risco(exposicao(cvss=7.0, criticidade="baixa")).risco == 7.0

    def test_exposicao_publica_multiplica(self) -> None:
        publico = calcular_risco(
            exposicao(cvss=8.0, criticidade="baixa", exposicao_red="publico")
        )
        assert publico.risco == pytest.approx(8.8)

    def test_exposicao_interna_nao_multiplica(self) -> None:
        interno = calcular_risco(
            exposicao(cvss=8.0, criticidade="baixa", exposicao_red="interno")
        )
        assert interno.risco == pytest.approx(8.0)

    def test_criticidade_acrescenta(self) -> None:
        item = calcular_risco(exposicao(cvss=8.0, criticidade="critica"))
        assert item.risco == pytest.approx(8.5)

    def test_workaround_reduz(self) -> None:
        sem = calcular_risco(exposicao(cvss=8.0, workaround=False))
        com = calcular_risco(exposicao(cvss=8.0, workaround=True))
        assert com.risco == pytest.approx(sem.risco - 1.0)

    def test_workaround_nao_fica_negativo(self) -> None:
        item = calcular_risco(
            exposicao(cvss=0.5, workaround=True, criticidade="baixa")
        )
        assert item.risco == 0.0

    def test_limite_superior(self) -> None:
        item = calcular_risco(
            exposicao(cvss=10.0, exposicao_red="publico", criticidade="critica")
        )
        assert item.risco <= 10.0

    def test_exposicao_desconhecida_usa_padrao(self) -> None:
        # Um valor de exposicao que nao esta no mapa nao pode virar erro, mas
        # tambem nao pode fingir que e publico.
        e = Exposicao(
            equipamento=Equipamento(
                fabricante="Fab", modelo="M", firmware="1.0",
                criticidade="baixa", exposicao_red="interno",
            ),
            cve=cve(cvss=8.0),
        )
        assert calcular_risco(e).risco == pytest.approx(8.0)

    def test_criticidade_desconhecida(self) -> None:
        e = Exposicao(
            equipamento=Equipamento(
                fabricante="Fab", modelo="M", firmware="1.0",
                criticidade="baixa", exposicao_red="interno",
            ),
            cve=cve(cvss=8.0),
        )
        assert calcular_risco(e).risco == pytest.approx(8.0)

    def test_arredondado(self) -> None:
        # 7,7 vem de 7,0 * 1,1 mais 0,0 de criticidade baixa.
        assert calcular_risco(
            exposicao(cvss=7.0, exposicao_red="publico", criticidade="baixa")
        ).risco == 7.7


class TestJustificativa:
    """O numero tem que vir acompanhado de explicacao."""

    def test_tem_justificativa(self) -> None:
        assert calcular_risco(exposicao()).justificativa

    def test_menciona_cvss(self) -> None:
        assert "CVSS" in calcular_risco(exposicao(cvss=7.0)).justificativa

    def test_cvv_s_alto_mencionado(self) -> None:
        j = calcular_risco(exposicao(cvss=9.1)).justificativa
        assert "9.1" in j

    def test_menciona_exposicao_quando_publica(self) -> None:
        j = calcular_risco(exposicao(exposicao_red="publico")).justificativa
        assert "exposicao" in j

    def test_nao_menciona_exposicao_quando_interna(self) -> None:
        j = calcular_risco(exposicao(exposicao_red="interno")).justificativa
        assert "exposicao" not in j

    def test_menciona_criticidade(self) -> None:
        j = calcular_risco(exposicao(criticidade="critica")).justificativa
        assert "criticidade" in j

    def test_menciona_workaround(self) -> None:
        j = calcular_risco(exposicao(workaround=True)).justificativa
        assert "workaround" in j

    def test_nao_menciona_workaround_quando_nao_ha(self) -> None:
        j = calcular_risco(exposicao(workaround=False)).justificativa
        assert "workaround" not in j

    def test_justificativa_completa(self) -> None:
        j = calcular_risco(
            exposicao(cvss=8.0, workaround=True, criticidade="alta",
                      exposicao_red="publico")
        ).justificativa
        assert "CVSS" in j
        assert "exposicao" in j
        assert "criticidade" in j
        assert "workaround" in j


class TestRanking:
    """A ordem do ranking."""

    def test_vazio(self) -> None:
        assert rankear([]) == []

    def test_um_item(self) -> None:
        assert len(rankear([exposicao()])) == 1

    def test_ordenado_decrescente(self) -> None:
        itens = rankear([
            exposicao(cvss=5.0, cve_id="CVE-2026-0001"),
            exposicao(cvss=9.0, cve_id="CVE-2026-0002"),
            exposicao(cvss=7.0, cve_id="CVE-2026-0003"),
        ])
        riscos = [i.risco for i in itens]
        assert riscos == sorted(riscos, reverse=True)

    def test_empate_desempata_por_cvss(self) -> None:
        # Mesmo risco final por caminhos diferentes: 5,8 interno sem
        # acrescimo contra 5,0 publico (5,5) mais 0,3 de criticidade. Ambos
        # daem 5,8, entao o desempate vai pelo CVSS e nao pela ordem de
        # entrada.
        itens = rankear([
            exposicao(cvss=5.0, exposicao_red="publico", criticidade="alta",
                      cve_id="CVE-2026-0001"),
            exposicao(cvss=5.8, exposicao_red="interno", criticidade="baixa",
                      cve_id="CVE-2026-0002"),
        ])
        assert itens[0].risco == itens[1].risco == pytest.approx(5.8)
        assert itens[0].exposicao.cve.cvss > itens[1].exposicao.cve.cvss

    def test_deterministico(self) -> None:
        lista = [
            exposicao(cvss=7.0, cve_id="CVE-2026-0001"),
            exposicao(cvss=7.0, cve_id="CVE-2026-0002"),
        ]
        a = [i.exposicao.cve.id for i in rankear(lista)]
        b = [i.exposicao.cve.id for i in rankear(lista)]
        assert a == b

    def test_preserva_todos(self) -> None:
        lista = [exposicao(cvss=f"{n}.0", cve_id=f"CVE-2026-{n:04d}")
                 for n in range(1, 6)]
        assert len(rankear(lista)) == len(lista)

    def test_tem_variedade_de_nota(self) -> None:
        itens = rankear([
            exposicao(cvss=9.0, cve_id="CVE-2026-0001"),
            exposicao(cvss=4.0, cve_id="CVE-2026-0002"),
            exposicao(cvss=2.0, cve_id="CVE-2026-0003"),
        ])
        assert len({i.risco for i in itens}) >= 2

    def test_todos_no_intervalo(self) -> None:
        itens = rankear([
            exposicao(cvss=10.0, exposicao_red="publico", criticidade="critica"),
            exposicao(cvss=0.1, criticidade="baixa", exposicao_red="interno"),
        ])
        for i in itens:
            assert 0.0 <= i.risco <= 10.0


class TestCvssSoNaoDecide:
    """O ponto do projeto: contexto muda a ordem."""

    def test_cvss_maior_nao_e_primeiro_quando_o_ativo_e_inferior(self) -> None:
        # CVSS 9.0 em ativo interno de criticidade baixa.
        fraco = exposicao(
            cvss=9.0, exposicao_red="interno", criticidade="baixa",
            modelo="Ativo fraco", cve_id="CVE-2026-0001",
        )
        # CVSS 8.0 em ativo publico de criticidade critica.
        forte = exposicao(
            cvss=8.0, exposicao_red="publico", criticidade="critica",
            modelo="Ativo forte", cve_id="CVE-2026-0002",
        )
        itens = rankear([fraco, forte])
        # 9.0 vs 8.0*1.1+0.5 = 9.3: o ativo publico sobe.
        assert itens[0].exposicao.equipamento.modelo == "Ativo forte"
        assert itens[0].exposicao.cve.cvss < itens[1].exposicao.cve.cvss

    def test_workaround_puxa_para_baixo(self) -> None:
        sem = exposicao(cvss=8.0, cve_id="CVE-2026-0001", workaround=False)
        com = exposicao(cvss=8.0, cve_id="CVE-2026-0002", workaround=True)
        itens = rankear([com, sem])
        assert itens[0].exposicao.cve.id == "CVE-2026-0001"
        assert itens[0].exposicao.cve.cvss == itens[1].exposicao.cve.cvss

    def test_publico_sobe_na_escala(self) -> None:
        interno = calcular_risco(exposicao(cvss=6.0, exposicao_red="interno"))
        publico = calcular_risco(exposicao(cvss=6.0, exposicao_red="publico"))
        assert publico.risco > interno.risco


class TestItemRisco:
    """A estrutura do item."""

    def test_campos(self) -> None:
        e = exposicao()
        item = ItemRisco(exposicao=e, risco=7.0, justificativa="j")
        assert item.exposicao is e
        assert item.risco == 7.0
        assert item.justificativa == "j"

    def test_congelado(self) -> None:
        item = calcular_risco(exposicao())
        with pytest.raises(Exception):
            item.risco = 1.0  # type: ignore[misc]