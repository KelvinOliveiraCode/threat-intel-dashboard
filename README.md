<div align="center">

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-189%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-96%25-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square" alt="Windows">
</p>

</div>

# threat-intel-dashboard

Cruza um inventário local de equipamentos com uma base de vulnerabilidades embarcada e gera um relatório de exposição priorizado por risco em HTML autocontido.

> **Os dados deste repositório são fictícios.** As 81 CVEs usam o padrão `CVE-2026-XXXXX` e foram inventadas para exercitar a priorização. Nenhuma corresponde a uma vulnerabilidade real publicada. Os equipamentos também são fictícios — os modelos existem no mercado, mas combinações de fabricante/modelo/firmware aqui não descrevem nenhum ambiente real.

### O que é

Ferramenta de priorização de exposição de vulnerabilidades: cruza um inventário local de equipamentos contra uma base de CVEs e devolve um ranking de exposição com uma justificativa numérica aberta em um arquivo HTML autocontido.

### Por que foi feito

Clientes e equipes de infraestrutura pedem esse cruzamento o tempo todo: "quais destes 300 equipamentos estão afetados por alguma falha conhecida?". A resposta manual leva horas, e a resposta errada sai quando alguém ordena a fila só pelo CVSS. O CVSS mede a gravidade técnica da falha, não o custo de perder aquele ativo específico — e é exatamente essa distinção que decide o que você conserta primeiro. O `intelhub` faz o cruzamento em segundos e, o ponto importante, não deixa o CVSS decidir sozinho: ele combina a nota da falha com exposição de rede, criticidade do ativo e existência de workaround, e mostra a conta aberta na coluna *Justificativa*, para você auditar e discordar.

### Como rodar

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m pytest tests/ -v
python -m intelhub cruzar --help
```

Saída real do subcomando, com a venv ativa:

```
usage: intelhub cruzar [-h] --saida SAIDA inventario cves

positional arguments:
  inventario     Caminho do JSON do inventario.
  cves           Caminho do JSON de CVEs.

options:
  -h, --help     show this help message and exit
  --saida SAIDA  Caminho do HTML de saida.
```

Para gerar o relatório:

```powershell
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida exemplos/relatorio-exposicao.html
```

Saída real:

```
Equipamentos inventariados: 13
CVEs na base: 81
Exposicoes encontradas: 73
Relatorio gravado em: exemplos\relatorio-exposicao.html
```

Para rodar sem instalar nada, aponte o PYTHONPATH para `src`:

```powershell
$env:PYTHONPATH="C:\Users\Kelvin\Desktop\portfolio-24\threat-intel-dashboard\src"
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida relatorio.html
```

### O que aprendi

1. **Comparar firmware é aritmética, não texto.** Um `str` diria que `"9.10" < "9.2"`, porque o primeiro caractere divergente já decide. Decisão: normalizar preenchendo zeros à direita e elevar as partes a inteiro. Consequência: `"9.10.0"` é classificado como mais novo que `"9.2.0"`, como deve ser.

2. **Versão não numérica vira erro, não "0".** `"7.4.3-rc1"` ou `"unknown"` levantam `VersaoInvalida`. Se virassem `0`, comparariam como anteriores a tudo e gerariam um falso positivo de exposição. Consequência: só firmwares bem formados são comparados; o resto é rejeitado com erro claro.

3. **Multiplicar na exposição, somar na criticidade.** Exposição de rede é agravante de probabilidade — um scanner da internet alcança todo mundo, então o risco sobe na proporção (10%). Criticidade é agravante de consequência — perder o core derruba o prédio inteiro, então é um peso fixo. Consequência: o modelo reage de jeito diferente a um `CVSS 9.1` num switch de core do que num ponto de acesso de andar.

4. **Desempate por (risco, cvss, id) para determinismo.** Dois itens com o mesmo risco precisam aparecer sempre na mesma ordem, senão o diff do Git do relatório enche de mudança falsa e ninguém confia no versionamento. O `tools/verificar_aceite.py` exige que o total do resumo bata com o ranking real, só para pegar deriva do código. Consequência: o mesmo comando, qualquer dia, mesma ordem.

5. **Teto e piso da fórmula de risco.** O risco é limitado a `[0.0, 10.0]`. Sem o teto, um item apareceria com "11.3" numa coluna que vai até 10 e quebraria qualquer regra externa que lesse a coluna. Consequência: números sempre dentro da escala, e a conta batendo com a justificativa.

### Limitações

Ditas de frente, porque um relatório de segurança que esconde o próprio alcance não serve para nada:

- **Não há probabilidade de exploração.** Todo item exposto pesa igual, sem considerar histórico de ataque ou threat intel.
- **Não há dependência entre itens.** Três CVEs no mesmo switch continuam sugerindo três manutenções separadas, quando na prática é uma janela só.
- **O desconto de 1.0 por workaround é um valor arbitrário.** Está assim porque é auditável e discutível, não porque saiu de um modelo.
- **A base é fictícia.** Para uso real, substitua `dados/cves-ficticias.json` por dados do NVD ou do seu fornecedor e ajuste o peso do contexto.

### Licença

MIT. Veja [`LICENSE`](LICENSE).

## EN

### What it is

Risk-prioritized exposure-reporting tool: it crosses a local equipment inventory against a local CVE database and returns a ranked exposure list with an open numerical justification, in a self-contained HTML file.

### Why it was built

Clients and infrastructure teams ask for this cross-reference all the time: "which of these 300 devices are affected by some known flaw?". The manual answer takes hours, and the wrong answer comes out when someone orders the queue by CVSS alone. CVSS measures the technical severity of the flaw, not the cost of losing that specific asset — and that is exactly what decides what you fix first. `intelhub` does the cross-reference in seconds and, the important point, does not let CVSS decide alone: it combines the flaw score with network exposure, asset criticality, and the existence of a workaround, and shows the open calculation in the *Justification* column, so you can audit and disagree.

### How to run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m pytest tests/ -v
python -m intelhub cruzar --help
```

Real output of the subcommand, with the venv active:

```
usage: intelhub cruzar [-h] --saida SAIDA inventario cves

positional arguments:
  inventario     Caminho do JSON do inventario.
  cves           Caminho do JSON de CVEs.

options:
  -h, --help     show this help message and exit
  --saida SAIDA  Caminho do HTML de saida.
```

To generate the report:

```powershell
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida exemplos/relatorio-exposicao.html
```

Real output:

```
Equipamentos inventariados: 13
CVEs na base: 81
Exposicoes encontradas: 73
Relatorio gravado em: exemplos\relatorio-exposicao.html
```

To run without installing anything, set PYTHONPATH to `src`:

```powershell
$env:PYTHONPATH="C:\Users\Kelvin\Desktop\portfolio-24\threat-intel-dashboard\src"
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida relatorio.html
```

### What I learned

1. **Comparing firmware is arithmetic, not text.** A `str` would say `"9.10" < "9.2"`, because the first diverging character decides. Decision: normalize by padding with zeros to the right and casting the parts to integers. Consequence: `"9.10.0"` is classified as newer than `"9.2.0"`, as it should be.

2. **Non-numeric versions become an error, not "0".** `"7.4.3-rc1"` or `"unknown"` raise `VersaoInvalida`. If they became `0`, they would compare as older than everything and generate a false positive of exposure. Consequence: only well-formed firmwares are compared; the rest are rejected with a clear error.

3. **Multiply on exposure, add criticality.** Network exposure is a probability aggravant — a scanner from the internet reaches everyone, so risk goes up proportionally (10%). Asset criticality is a consequence aggravant — losing the core takes the whole building down, so it is a fixed weight. Consequence: the model reacts differently to a `CVSS 9.1` on a core switch than on a floor access point.

4. **Tie-break by (risk, cvss, id) for determinism.** Two items with the same risk must always appear in the same order, otherwise the Git diff of the report fills with fake changes and nobody trusts versioning. `tools/verificar_aceite.py` requires that the summary total matches the real ranking, just to catch code drift. Consequence: the same command, any day, same order.

5. **Ceiling and floor of the risk formula.** Risk is clamped to `[0.0, 10.0]`. Without the ceiling, an item would show "11.3" in a column that goes up to 10 and break any external rule that reads the column. Consequence: numbers always inside the scale, and the calculation matching the justification.

### Limitations

Said straight, because a security report that hides its own reach is useless:

- **No exploit probability.** Every exposed item weighs the same, without considering attack history or threat intel.
- **No dependency between items.** Three CVEs on the same switch keep suggesting three separate maintenance windows, when in practice it is one window.
- **The 1.0 discount for workaround is an arbitrary value.** It is like this because it is auditable and debatable, not because it came from a model.
- **The database is fictitious.** For real use, replace `dados/cves-ficticias.json` with data from NVD or your vendor and adjust the context weight.

### License

MIT. See [`LICENSE`](LICENSE).

## Como funciona

Quatro etapas, uma por módulo:

```
inventario.json ──┐
                  ├─► cruzamento ─► priorizacao ─► relatorio ─► .html
cves.json ────────┘
```

| Módulo | Responsabilidade |
|--------|------------------|
| `inventario.py` | Lê e valida o inventário: fabricante, modelo, firmware, criticidade, exposição |
| `cvedb.py` | Carrega a base de CVEs e compara versão com alinhamento por zeros |
| `cruzamento.py` | Casa CVE com equipamento por fabricante + modelo + faixa afetada |
| `priorizacao.py` | Calcula o risco e devolve o ranking com justificativa |
| `relatorio.py` | Gera o HTML autocontido, agrupado por ativo |
| `cli.py` | A linha de comando |

### O detalhe da comparação de versão

Comparar firmware é aritmética, não comparação de texto. Um `str` diria que `"9.10" < "9.2"`, porque `1 < 2` no primeiro caractere divergente.

O `intelhub` normaliza antes de comparar, preenchendo com zeros à direita:

| Firmware | versus | Resultado |
|----------|---------|-----------|
| `9` | `9.2.0` | mesma versão |
| `9.2` | `9.2.0` | mesma versão |
| `9.2.1` | `9.2.0` | mais novo |
| `9.10.0` | `9.2.0` | mais novo (não menor, como o `str` diria) |

Versão não numérica — `7.4.3-rc1`, `unknown` — levanta `VersaoInvalida` em vez de virar `0`, que compararia como anterior a tudo e geraria um falso positivo de exposição.

### A fórmula de risco

```
risco = cvss × fator_exposição + acréscimo_criticidade − (1.0 se houver workaround)
```

Limitado a `[0.0, 10.0]`. O detalhamento e os limites do método estão em [`docs/metodo-de-priorizacao.md`](docs/metodo-de-priorizacao.md), e o que é CVSS, vetor de ataque e por que a nota sozinha não decide prioridade está em [`docs/como-funciona-o-cvss.md`](docs/como-funciona-o-cvss.md).

## Formato dos dados

**`dados/inventario-equipamentos.json`** — lista de equipamentos:

```json
{
  "fabricante": "Palo Alto",
  "modelo": "PA-3220",
  "firmware": "10.1.0",
  "criticidade": "alta",
  "exposicao_red": "publico"
}
```

`criticidade` aceita `critica`, `alta`, `media`, `baixa`.
`exposicao_red` aceita `publico`, `interno`.

**`dados/cves-ficticias.json`** — lista de vulnerabilidades fictícias:

```json
{
  "id": "CVE-2026-8001",
  "description": "[CVE-2026-8001] Falha de seguranca registrada em laboratorio. Vetor: AV:N AC:L PR:N.",
  "cvss": 10.0,
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "affected_version": "10.0.0 - 10.1.0",
  "manufacturer": "Palo Alto",
  "model": "PA-3220",
  "workaround": false
}
```

`affected_version` aceita uma versão (`15.2.4`) ou uma faixa (`8.7.0 - 8.7.1`).
`workaround` indica se o fabricante já publicou correção. O `model` do CVE usa o nome do campo em inglês porque é o nome que o formato CVE já usa; os módulos internos usam `modelo`, como todo o resto do código.

## Uso como biblioteca

```python
from intelhub.cruzamento import cruzar
from intelhub.cvedb import carregar_cves
from intelhub.inventario import carregar_inventario
from intelhub.priorizacao import rankear
from intelhub.relatorio import gerar_relatorio_html

inventario = carregar_inventario("dados/inventario-equipamentos.json")
cves = carregar_cves("dados/cves-ficticias.json")

ranking = rankear(cruzar(inventario, cves))

for item in ranking[:5]:
    eq = item.exposicao.equipamento
    print(f"{item.risco:5.2f}  {item.exposicao.cve.id}  {eq.fabricante} {eq.modelo}")
    print(f"        {item.justificativa}")
```

```
10.00  CVE-2026-8001  Palo Alto PA-3220
        CVSS 10.0; exposicao 1.1x; criticidade +0.3
10.00  CVE-2026-6001  MikroTik CCR2004
        CVSS 9.8; exposicao 1.1x; criticidade +0.1
10.00  CVE-2026-5001  NetApp FAS2700
        CVSS 9.8; criticidade +0.5
```

## Testes

```powershell
python -m pytest tests/ -v
```

189 testes, 96% de cobertura. Cobrem a comparação de versão, o casamento de faixa, o teto e o piso da fórmula de risco, o escape de HTML (o relatório recebe texto de arquivo e não pode deixar `<script>` passar cru), a ordenação determinística e a CLI inteira.

Verificações que a suíte não cobre sozinha:

```powershell
python tools/verificar_aceite.py       # 12 expostos, 1 limpo, ranking ordenado
python tools/verificar_encoding.py     # nenhum caractere corrompido
python tools/verificar_exemplo_limpo.py # exemplo limpo existe
python tools/gerar_exemplos.py         # regera o exemplo de forma determinística
```

O `verificar_aceite.py` inclui um equipamento **limpo** — o `FortiGate 60F` com firmware `7.4.3`, acima da faixa afetada. Sem um caso negativo, um filtro que devolvesse tudo já passaria nos testes.

## Estrutura

```
threat-intel-dashboard/
├── src/intelhub/            # o pacote
├── dados/                   # inventário e base de CVEs fictícias
├── docs/                    # CVSS e método de priorização
├── exemplos/                # relatório HTML gerado
├── tests/                   # 189 testes
└── tools/                   # gerador de dados e verificações
```
