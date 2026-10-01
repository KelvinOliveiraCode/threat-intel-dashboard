"""Testes do cruzamento entre inventario e CVEs.

Inventory/CVE cross-reference tests.

O cruzamento precisa filtrar em duas etapas: primeiro fabricante e modelo, depois
a faixa de versao. Os testes cobrem as duas, porque um filtro que casa o
fabricante mas ignora a versao transformaria qualquer equipamento em um alvo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intelhub.cruzamento import Exposicao, cruzar
from intelhub.cvedb import CVE, carregar_cves
from intelhub.inventario import Equipamento, carregar_inventario

RAIZ = Path(__file__).resolve().parent.parent
INVENTARIO = RAIZ / "dados" / "inventario-equipamentos.json"
CVES = RAIZ / "dados" / "cves-ficticias.json"


@pytest.fixture(scope="module")
def inventario() -> list[Equipamento]:
    """O inventario que acompanha o repositorio."""
    return carregar_inventario(INVENTARIO)


@pytest.fixture(scope="module")
def cves() -> list[CVE]:
    """A base de CVEs que acompanha o repositorio."""
    return carregar_cves(CVES)


def cve_de(
    cve_id: str = "CVE-2026-9999",
    fabricante: str = "Fortinet",
    modelo: str = "FortiGate 60F",
    faixa: str = "7.0.0 - 7.4.1",
    cvss: float = 7.5,
    workaround: bool = False,
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
        manufacturer=fabricante,
        model=modelo,
        workaround=workaround,
    )


def equipamento(
    fabricante: str = "Fortinet",
    modelo: str = "FortiGate 60F",
    firmware: str = "7.4.1",
    criticidade: str = "alta",
    exposicao: str = "publico",
) -> Equipamento:
    """Fabrica um equipamento para um teste.

    Build an equipment item for a test.
    """
    return Equipamento(
        fabricante=fabricante,
        modelo=modelo,
        firmware=firmware,
        criticidade=criticidade,
        exposicao_red=exposicao,
    )


class TestInventario:
    """Leitura do inventario."""

    def test_carrega_todos(self, inventario: list[Equipamento]) -> None:
        assert len(inventario) >= 10

    def test_campos_preenchidos(self, inventario: list[Equipamento]) -> None:
        for eq in inventario:
            assert eq.fabricante
            assert eq.modelo
            assert eq.firmware
            assert eq.criticidade in ("baixa", "media", "alta", "critica")
            assert eq.exposicao_red in ("publico", "interno")

    def test_tem_exposicao_e_interno(self, inventario: list[Equipamento]) -> None:
        exposicoes = {e.exposicao_red for e in inventario}
        assert exposicoes == {"publico", "interno"}

    def test_tem_criticidade_critica(self, inventario: list[Equipamento]) -> None:
        assert any(e.criticidade == "critica" for e in inventario)

    def test_arquivo_inexistente(self) -> None:
        with pytest.raises(OSError):
            carregar_inventario(RAIZ / "nao-existe.json")

    def test_topo_nao_lista(self, tmp_path: Path) -> None:
        f = tmp_path / "x.json"
        f.write_text('{"a": 1}', encoding="utf-8")
        with pytest.raises(ValueError, match="lista"):
            carregar_inventario(f)

    def test_criticidade_invalida(self, tmp_path: Path) -> None:
        f = tmp_path / "x.json"
        f.write_text(json.dumps([{
            "fabricante": "A", "modelo": "B", "firmware": "1.0",
            "criticidade": "altissima", "exposicao_red": "interno",
        }]), encoding="utf-8")
        with pytest.raises(ValueError, match="criticidade"):
            carregar_inventario(f)

    def test_exposicao_invalida(self, tmp_path: Path) -> None:
        f = tmp_path / "x.json"
        f.write_text(json.dumps([{
            "fabricante": "A", "modelo": "B", "firmware": "1.0",
            "criticidade": "alta", "exposicao_red": "meio-termo",
        }]), encoding="utf-8")
        with pytest.raises(ValueError, match="exposicao_red"):
            carregar_inventario(f)

    def test_sem_fabricante(self) -> None:
        with pytest.raises(ValueError, match="obrigatorios"):
            Equipamento("", "B", "1.0", "alta", "interno")

    def test_sem_firmware(self) -> None:
        with pytest.raises(ValueError, match="firmware"):
            Equipamento("A", "B", "", "alta", "interno")


class TestBaseCves:
    """Leitura da base de CVEs."""

    def test_carrega_todas(self, cves: list[CVE]) -> None:
        assert len(cves) >= 60

    def test_todas_ficticias(self, cves: list[CVE]) -> None:
        for cve in cves:
            assert cve.id.startswith("CVE-2026-")

    def test_ids_unicos(self, cves: list[CVE]) -> None:
        ids = [c.id for c in cves]
        assert len(ids) == len(set(ids))

    def test_cvss_no_intervalo(self, cves: list[CVE]) -> None:
        for cve in cves:
            assert 0.0 <= cve.cvss <= 10.0

    def test_tem_cvss_alto(self, cves: list[CVE]) -> None:
        assert any(c.cvss >= 9.0 for c in cves)

    def test_tem_workaround(self, cves: list[CVE]) -> None:
        assert any(c.workaround for c in cves)
        assert any(not c.workaround for c in cves)

    def test_tem_descricao(self, cves: list[CVE]) -> None:
        assert all(cve.description for cve in cves)

    def test_vetor_cvss(self, cves: list[CVE]) -> None:
        assert all(cve.vector.startswith("CVSS:3.1/") for cve in cves)

    def test_tem_varios_fabricantes(self, cves: list[CVE]) -> None:
        assert len({c.manufacturer for c in cves}) >= 8

    def test_id_fora_do_formato(self) -> None:
        with pytest.raises(ValueError, match="CVE-2026-"):
            cve_de(cve_id="CVE-2021-1234")

    def test_cvss_fora_do_intervalo(self) -> None:
        with pytest.raises(ValueError, match="range"):
            cve_de(cvss=11.0)

    def test_faixa_vazia(self) -> None:
        with pytest.raises(ValueError, match="affected_version"):
            cve_de(faixa="")

    def test_arquivo_inexistente(self) -> None:
        with pytest.raises(OSError):
            carregar_cves(RAIZ / "nao-existe.json")

    def test_topo_nao_lista(self, tmp_path: Path) -> None:
        f = tmp_path / "x.json"
        f.write_text('{"a": 1}', encoding="utf-8")
        with pytest.raises(ValueError, match="lista"):
            carregar_cves(f)


class TestCruzarFabricanteEModelo:
    """Primeira etapa do filtro."""

    def test_casa_exato(self) -> None:
        r = cruzar([equipamento()], [cve_de()])
        assert len(r) == 1

    def test_fabricante_diferente(self) -> None:
        r = cruzar(
            [equipamento(fabricante="Cisco")],
            [cve_de(fabricante="Fortinet")],
        )
        assert r == []

    def test_modelo_diferente(self) -> None:
        assert cruzar([equipamento(modelo="FortiGate 200F")], [cve_de()]) == []

    def test_caixa_diferente(self) -> None:
        # Comparacao de fabricante e modelo e sem distincao de caixa.
        r = cruzar(
            [equipamento(fabricante="FORTINET", modelo="fortigate 60f")],
            [cve_de()],
        )
        assert len(r) == 1

    def test_espaco_nas_pontas(self) -> None:
        eq = Equipamento(
            fabricante="  Fortinet  ", modelo=" FortiGate 60F ",
            firmware="7.4.1", criticidade="alta", exposicao_red="publico",
        )
        assert len(cruzar([eq], [cve_de()])) == 1

    def test_cve_de_outro_fabricante_nao_entra(self) -> None:
        r = cruzar(
            [equipamento()],
            [cve_de(), cve_de(cve_id="CVE-2026-9998", fabricante="Cisco")],
        )
        assert all(e.cve.manufacturer == "Fortinet" for e in r)


class TestCruzarVersao:
    """Segunda etapa do filtro: a faixa de versao."""

    def test_dentro_da_faixa(self) -> None:
        assert len(cruzar([equipamento(firmware="7.4.1")], [cve_de()])) == 1

    def test_fora_da_faixa(self) -> None:
        assert cruzar([equipamento(firmware="7.4.2")], [cve_de()]) == []

    def test_no_inicio_da_faixa(self) -> None:
        assert len(cruzar([equipamento(firmware="7.0.0")], [cve_de()])) == 1

    def test_no_fim_da_faixa(self) -> None:
        assert len(cruzar([equipamento(firmware="7.4.1")], [cve_de()])) == 1

    def test_abaixo_da_faixa(self) -> None:
        assert cruzar([equipamento(firmware="6.4.0")], [cve_de()]) == []

    def test_igualdade_exata(self) -> None:
        r = cruzar(
            [equipamento(firmware="7.2.0")], [cve_de(faixa="7.2.0")]
        )
        assert len(r) == 1

    def test_operador_maior_igual(self) -> None:
        assert len(cruzar([equipamento(firmware="7.4.1")],
                          [cve_de(faixa=">=7.0.0")])) == 1
        assert cruzar([equipamento(firmware="6.9.0")],
                      [cve_de(faixa=">=7.0.0")]) == []

    def test_operador_menor(self) -> None:
        assert len(cruzar([equipamento(firmware="7.0.1")],
                          [cve_de(faixa="<7.4.1")])) == 1

    def test_versao_mais_curta_que_a_faixa(self) -> None:
        # 7.4 e o mesmo que 7.4.0. Sem alinhar as tuplas, isso daria falso.
        assert len(cruzar([equipamento(firmware="7.4")], [cve_de()])) == 1

    def test_fim_do_intervalo_mais_curto(self) -> None:
        # A ponta final do intervalo e "7.4", e o firmware e "7.4.0". Sem
        # alinhar as tuplas, (7,4,0) > (7,4) e o equipamento sairia da faixa.
        assert len(cruzar([equipamento(firmware="7.4.0")],
                          [cve_de(faixa="7.0.0 - 7.4")])) == 1

    def test_faixa_invertida_nao_casa(self) -> None:
        # Inicio maior que o fim: nao ha versao que satisfaca, e nao ha erro.
        assert cruzar([equipamento(firmware="8.0.0")],
                      [cve_de(faixa="9.0.0 - 7.4")]) == []

    def test_mais_um_digito(self) -> None:
        assert cruzar([equipamento(firmware="10.0")],
                      [cve_de(faixa="9.0.0 - 9.9.9")]) == []


class TestCruzarInventarioReal:
    """Sobre os dados que acompanham o repositorio."""

    def test_encontra_exposicoes(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        assert len(cruzar(inventario, cves)) >= 6

    def test_encontra_pelo_menos_seis_equipamentos(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        atingidos = {e.equipamento.firmware for e in cruzar(inventario, cves)}
        assert len(atingidos) >= 6

    def test_tem_equipamento_limpo(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        expostos = {
            (e.equipamento.fabricante, e.equipamento.modelo, e.equipamento.firmware)
            for e in cruzar(inventario, cves)
        }
        todos = {(e.fabricante, e.modelo, e.firmware) for e in inventario}
        # Um equipamento sem exposicao e o que prova que o filtro funciona.
        assert todos - expostos

    def test_limpo_e_o_firmware_corrigido(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        expostos = {
            (e.equipamento.fabricante, e.equipamento.modelo, e.equipamento.firmware)
            for e in cruzar(inventario, cves)
        }
        limpos = {
            (e.fabricante, e.modelo, e.firmware) for e in inventario
        } - expostos
        # Mesmo modelo do item exposto, firmware acima de todas as faixas.
        assert limpos == {("Fortinet", "FortiGate 60F", "7.4.3")}

    def test_filtro_de_versao_discrimina(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        # Pelo menos um equipamento tem CVE do mesmo modelo que nao o atinge,
        # o que prova que a faixa de versao esta sendo usada.
        discriminou = False
        for eq in inventario:
            do_modelo = [
                c for c in cves
                if c.manufacturer.lower() == eq.fabricante.lower()
                and c.model.lower() == eq.modelo.lower()
            ]
            atingidos = len(cruzar([eq], cves))
            if len(do_modelo) > atingidos:
                discriminou = True
        assert discriminou

    def test_cv_e_de_equipamento_ausente_nao_entra(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        modelos = {(e.fabricante.lower(), e.modelo.lower()) for e in inventario}
        for exposicao in cruzar(inventario, cves):
            par = (
                exposicao.cve.manufacturer.lower(),
                exposicao.cve.model.lower(),
            )
            assert par in modelos

    def test_resultado_deterministico(
        self, inventario: list[Equipamento], cves: list[CVE]
    ) -> None:
        a = [(e.equipamento.modelo, e.cve.id) for e in cruzar(inventario, cves)]
        b = [(e.equipamento.modelo, e.cve.id) for e in cruzar(inventario, cves)]
        assert a == b

    def test_sem_inventario(self, cves: list[CVE]) -> None:
        assert cruzar([], cves) == []

    def test_sem_cves(self, inventario: list[Equipamento]) -> None:
        assert cruzar(inventario, []) == []


class TestExposicao:
    """A estrutura de exposicao."""

    def test_guarda_a_faixa(self) -> None:
        with pytest.raises(ValueError, match="alcance"):
            Exposicao(equipamento=equipamento(firmware="9.9.9"), cve=cve_de())

    def test_aceita_quando_dentro(self) -> None:
        assert Exposicao(equipamento(), cve_de()).cve.id == "CVE-2026-9999"

    def test_congelada(self) -> None:
        e = Exposicao(equipamento(), cve_de())
        with pytest.raises(Exception):
            e.cve = cve_de()  # type: ignore[misc]