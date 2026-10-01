# intelhub

Cruza um inventário local de equipamentos com uma base de vulnerabilidades
embarcada e gera um **relatório de exposição priorizado por risco**, em HTML
autocontido.

Cross-reference a local equipment inventory against an embedded vulnerability
database and produce a **risk-prioritized exposure report** as a
self-contained HTML file.

> **Os dados deste repositório são fictícios.** As 81 CVEs usam o padrão
> `CVE-2026-XXXXX` e foram inventadas para exercitar a priorização. Nenhuma
> corresponde a uma vulnerabilidade real publicada. Os equipamentos também são
> fictícios — os modelos existem no mercado, mas combinações de
> fabricante/modelo/firmware aqui não descrevem nenhum ambiente real.

## O problema que ele resolve

Clientes e equipes de infraestrutura pedem esse cruzamento o tempo todo: "quais
destes 300 equipamentos estão afetados por alguma falha conhecida?" A resposta
manual leva horas, e a resposta errada sai quando alguém ordena a fila só pelo
CVSS.

O `intelhub` faz o cruzamento em segundos e — o ponto importante — **não deixa
o CVSS decidir sozinho**. Ele combina a nota da falha com exposição de rede,
criticidade do ativo e existência de workaround, e mostra a conta aberta na
coluna *Justificativa*, para você auditar e discordar.

## Instalação

Zero dependências de runtime. Só Python 3.10 ou superior.

```powershell
git clone <url-do-repositorio>
cd threat-intel-dashboard
pip install -e ".[dev]"
```

## Uso

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

Um exemplo do relatório está versionado em
[`exemplos/relatorio-exposicao.html`](exemplos/relatorio-exposicao.html).

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

Comparar firmware é aritmética, não comparação de texto. Um `str` diria que
`"9.10" < "9.2"`, porque `1 < 2` no primeiro caractere divergente.

O `intelhub` normaliza antes de comparar, preenchendo com zeros à direita:

| Firmware | versus | Resultado |
|----------|---------|-----------|
| `9` | `9.2.0` | mesma versão |
| `9.2` | `9.2.0` | mesma versão |
| `9.2.1` | `9.2.0` | mais novo |
| `9.10.0` | `9.2.0` | mais novo (não menor, como o `str` diria) |

Versão não numérica — `7.4.3-rc1`, `unknown` — levanta `VersaoInvalida` em vez
de virar `0`, que compararia como anterior a tudo e geraria um falso positivo
de exposição.

### A fórmula de risco

```
risco = cvss × fator_exposição + acréscimo_criticidade − (1.0 se houver workaround)
```

Limitado a `[0.0, 10.0]`. O detalhamento e os limites do método estão em
[`docs/metodo-de-priorizacao.md`](docs/metodo-de-priorizacao.md), e o que é
CVSS, vetor de ataque e por que a nota sozinha não decide prioridade está em
[`docs/como-funciona-o-cvss.md`](docs/como-funciona-o-cvss.md).

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
`workaround` indica se o fabricante já publicou correção. O `model` do CVE usa
o nome do campo em inglês porque é o nome que o formato CVE já usa; os módulos
internos usam `modelo`, como todo o resto do código.

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

134 testes, 96% de cobertura. Cobrem a comparação de versão, o casamento de
faixa, o teto e o piso da fórmula de risco, o escape de HTML (o relatório
recebe texto de arquivo e não pode deixar `<script>` passar cru), a
ordenação determinística e a CLI inteira.

Verificações que a suíte não cobre sozinha:

```powershell
python tools/verificar_aceite.py    # 12 expostos, 1 limpo, ranking ordenado
python tools/verificar_encoding.py  # nenhum caractere corrompido
python tools/gerar_exemplos.py      # regera o exemplo de forma determinística
```

O `verificar_aceite.py` inclui um equipamento **limpo** — o `FortiGate 60F`
com firmware `7.4.3`, acima da faixa afetada. Sem um caso negativo, um filtro
que devolvesse tudo já passaria nos testes.

## Estrutura

```
threat-intel-dashboard/
├── src/intelhub/            # o pacote
├── dados/                   # inventário e base de CVEs fictícias
├── docs/                    # CVSS e método de priorização
├── exemplos/                # relatório HTML gerado
├── tests/                   # 134 testes
└── tools/                   # gerador de dados e verificações
```

## Limitações

Ditas de frente, porque um relatório de segurança que esconde o próprio alcance
não serve para nada:

- **Não há probabilidade de exploração.** Todo item exposto pesa igual, sem
  considerar histórico de ataque ou threat intel.
- **Não há dependência entre itens.** Três CVEs no mesmo switch continuam
  sugerindo três manutenções separadas, quando na prática é uma janela só.
- **O desconto de 1.0 por workaround é um valor arbitrário.** Está assim
  porque é auditável e discutível, não porque saiu de um modelo.
- **A base é fictícia.** Para uso real, substitua `dados/cves-ficticias.json`
  por dados do NVD ou do seu fornecedor e ajuste o peso do contexto.

## Licença

MIT.
