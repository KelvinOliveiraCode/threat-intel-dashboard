"""Testes do relatorio HTML e da CLI.

HTML report and CLI tests.

O relatorio recebe texto que vem de arquivo de dado, entao duas coisas sao
obrigatorias: ele precisa **escapar** esse texto, e ele precisa dizer de onde
saiu cada numero. Um relatorio de seguranca que mostra "undefined" no lugar do
CVSS e um relatorio em que ninguem confia.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intelhub.cli import construir_parser, main
from intelhub.cruzamento import Exposicao, cruzar
from intelhub.cvedb import carregar_cves
from intelhub.inventario import carregar_inventario
from intelhub.priorizacao import calcular_risco, rankear
from intelhub.relatorio import (
    _classe_risco,
    _esc,
    _recomendacao,
    gerar_relatorio_html,
)

RAIZ = Path(__file__).resolve().parent.parent
INVENTARIO = RAIZ / "dados" / "inventario-equipamentos.json"
CVES = RAIZ / "dados" / "cves-ficticias.json"


@pytest.fixture(scope="module")
def ranking():
    """Ranking real, calculado dos dados do repositorio."""
    inventario = carregar_inventario(INVENTARIO)
    cves = carregar_cves(CVES)
    return rankear(cruzar(inventario, cves))


class TestEscape:
    """Protecao contra injecao de markup vindo do dado."""

    def test_ampersand(self) -> None:
        assert _esc("a & b") == "a &amp; b"

    def test_menor(self) -> None:
        assert _esc("<b>") == "&lt;b&gt;"

    def test_aspas(self) -> None:
        assert _esc('a"b') == "a&quot;b"

    def test_texto_normal(self) -> None:
        assert _esc("CVE-2026-1001") == "CVE-2026-1001"

    def test_ampersand_antes_dos_outros(self) -> None:
        # Se & fosse escapado por ultimo, viraria &amp;lt; em vez de &lt;.
        assert _esc("<a>") == "&lt;a&gt;"


class TestClasseRisco:
    """A escala de cores por severidade."""

    @pytest.mark.parametrize("risco,esperada", [
        (10.0, "critico"), (7.0, "critico"), (6.99, "alto"),
        (4.0, "alto"), (3.99, "medio"), (2.0, "medio"),
        (1.99, "baixo"), (0.0, "baixo"),
    ])
    def test_faixa(self, risco: float, esperada: str) -> None:
        assert _classe_risco(risco) == esperada


class TestRecomendacao:
    """A recomendacao por item."""

    def test_com_workaround(self, ranking) -> None:
        item = next(i for i in ranking if i.exposicao.cve.workaround)
        texto = _recomendacao(item)
        assert "workaround" in texto
        assert item.exposicao.equipamento.modelo in texto

    def test_sem_workaround(self, ranking) -> None:
        item = next(i for i in ranking if not i.exposicao.cve.workaround)
        texto = _recomendacao(item)
        assert "Atualizar firmware" in texto
        assert item.exposicao.cve.affected_version in texto


class TestHtmlVazio:
    """Relatorio sem itens."""

    def test_nao_quebra(self) -> None:
        html = gerar_relatorio_html([])
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_mostra_zero(self) -> None:
        assert "0" in gerar_relatorio_html([])

    def test_sem_secao_de_ativo(self) -> None:
        assert "class=\"asset\"" not in gerar_relatorio_html([])


class TestHtmlComItens:
    """Relatorio com o ranking real."""

    def test_estrutura_basica(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert html.startswith("<!DOCTYPE html>")
        assert 'lang="pt-BR"' in html
        assert "<style>" in html

    def test_uma_secao_por_equipamento(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        expostos = {
            (i.exposicao.equipamento.fabricante, i.exposicao.equipamento.modelo)
            for i in ranking
        }
        assert html.count('class="asset"') == len(expostos)

    def test_uma_linha_por_item(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert html.count("<tr class=") == len(ranking)

    def test_mostra_a_justificativa(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert "CVSS" in html
        assert "exposicao" in html

    def test_mostra_a_recomendacao(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert "Aplicar workaround" in html or "Atualizar firmware" in html

    def test_resumo_com_contagens(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert "Itens avaliados" in html
        assert "Criticos ou altos" in html
        assert "Maior risco" in html
        assert "CVEs distintas" in html

    def test_resumo_bate_com_o_ranking(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        assert f"<strong>{len(ranking)}</strong>" in html

    def test_maior_risco_bate(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        maior = max(i.risco for i in ranking)
        assert f"{maior:.2f}" in html

    def test_cabecalho_de_tabela(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        for coluna in ("CVE", "Fabricante", "Modelo", "Firmware",
                       "Criticidade", "Exposicao", "Risco", "Justificativa",
                       "Recomendacao"):
            assert f"<th>{coluna}</th>" in html

    def test_marca_de_data(self, ranking) -> None:
        assert "Gerado em" in gerar_relatorio_html(
            ranking, caminho_gerado_em="2026-01-02 03:04"
        )

    def test_sem_data_nao_marca(self, ranking) -> None:
        assert "Gerado em" not in gerar_relatorio_html(ranking)

    def test_autocontido(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        for tag in ("<script", "<link", "<img", "<iframe", "cdn"):
            assert tag not in html

    def test_sem_caminho_absoluto(self, ranking) -> None:
        # O relatorio vai para commit e para issue; caminho de maquina nao entra.
        html = gerar_relatorio_html(ranking)
        assert "C:\\" not in html
        assert "/Users/" not in html

    def test_preserva_paleta_do_portfolio(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        # Preto, branco, cinza, com vermelho e azul so como acento.
        for cor in ("#111111", "#ffffff", "#6b6b6b", "#c62828", "#1565c0"):
            assert cor in html

    def test_classifica_seriedade_nas_linhas(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        for classe in ("critico", "alto", "medio", "baixo"):
            # Pelo menos uma das faixas tem que existir; baixo pode nao existir
            # se todo item tiver risco acima de 2.
            assert f'tr class="{classe}"' in html or classe == "baixo"

    def test_ordem_decrescente_dentro_do_ativo(self, ranking) -> None:
        html = gerar_relatorio_html(ranking)
        # A primeira tabela do relatorio e o ativo de maior risco.
        primeira = html.split("<tbody>")[1].split("</tbody>")[0]
        riscos = [
            float(linha.split("</td>")[6].split("<td>")[-1])
            for linha in primeira.split("<tr ")[1:]
        ]
        assert riscos == sorted(riscos, reverse=True)

    def test_utf8_valido(self, ranking) -> None:
        gerar_relatorio_html(ranking).encode("utf-8").decode("utf-8")


class TestHtmlEscapaDados:
    """Markup vindo do arquivo de dado nao pode entrar cru."""

    def test_descricao_com_markup(self, tmp_path: Path) -> None:
        from intelhub.cvedb import CVE
        from intelhub.inventario import Equipamento

        cve = CVE(
            id="CVE-2026-0001",
            description="<script>alert(1)</script>",
            cvss=9.0,
            vector="CVSS:3.1/AV:N",
            affected_version="1.0",
            manufacturer="Fab<script>",
            model="Mod<ulo>",
            workaround=False,
        )
        eq = Equipamento(
            fabricante="Fab<script>", modelo="Mod<ulo>", firmware="1.0",
            criticidade="alta", exposicao_red="interno",
        )
        html = gerar_relatorio_html([calcular_risco(Exposicao(eq, cve))])
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
        assert "Mod&lt;ulo&gt;" in html


class TestCli:
    """A linha de comando."""

    def test_gera_relatorio(self, tmp_path: Path, capsys) -> None:
        destino = tmp_path / "r.html"
        codigo = main([
            "cruzar", str(INVENTARIO), str(CVES), "--saida", str(destino)
        ])
        assert codigo == 0
        assert destino.exists()
        saida = capsys.readouterr().out
        assert "Equipamentos inventariados: 13" in saida
        assert "CVEs na base: 81" in saida

    def test_relatorio_tem_conteudo(self, tmp_path: Path) -> None:
        destino = tmp_path / "r.html"
        main(["cruzar", str(INVENTARIO), str(CVES), "--saida", str(destino)])
        html = destino.read_text(encoding="utf-8")
        assert "CVE-2026-" in html
        assert "Medidor" not in html  # nenhum texto de exemplo infiltrado

    def test_saida_utf8_valida(self, tmp_path: Path) -> None:
        destino = tmp_path / "r.html"
        main(["cruzar", str(INVENTARIO), str(CVES), "--saida", str(destino)])
        destino.read_bytes().decode("utf-8")

    def test_cria_diretorio(self, tmp_path: Path) -> None:
        destino = tmp_path / "a" / "b" / "r.html"
        main(["cruzar", str(INVENTARIO), str(CVES), "--saida", str(destino)])
        assert destino.exists()

    def test_inventario_inexistente(self, tmp_path: Path, capsys) -> None:
        codigo = main([
            "cruzar", "nao-existe.json", str(CVES),
            "--saida", str(tmp_path / "r.html"),
        ])
        assert codigo == 2
        assert "Erro" in capsys.readouterr().err

    def test_cves_inexistente(self, tmp_path: Path) -> None:
        codigo = main([
            "cruzar", str(INVENTARIO), "nao-existe.json",
            "--saida", str(tmp_path / "r.html"),
        ])
        assert codigo == 2

    def test_ajuda(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_ajuda_do_cruzar(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["cruzar", "--help"])
        assert exc.value.code == 0

    def test_sem_subcomando(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code != 0

    def test_faltando_argumento(self) -> None:
        with pytest.raises(SystemExit):
            main(["cruzar"])

    def test_parser_padroes(self) -> None:
        args = construir_parser().parse_args([
            "cruzar", "i.json", "c.json", "--saida", "r.html"
        ])
        assert args.inventario == "i.json"
        assert args.cves == "c.json"
        assert args.saida == "r.html"

    def test_saida_e_obrigatoria(self) -> None:
        # A CLI so produz relatorio em arquivo; sem --saida nao ha o que fazer.
        with pytest.raises(SystemExit):
            construir_parser().parse_args(["cruzar", "i.json", "c.json"])