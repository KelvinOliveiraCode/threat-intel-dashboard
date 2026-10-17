# intelhub

<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/tests-189%20passing-brightgreen?style=flat-square" alt="Tests">
<img src="https://img.shields.io/badge/coverage-96%25-brightgreen?style=flat-square" alt="Coverage">
<img src="https://img.shields.io/badge/deps-zero%20deps-brightgreen?style=flat-square" alt="Deps">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">

Cruza um inventário local de equipamentos com uma base de CVEs e gera um relatório de exposição priorizado em HTML autocontido.

> **Os dados deste repositório são fictícios.** As 81 CVEs usam o padrão `CVE-2026-XXXXX` e foram inventadas para exercitar a priorização. Nenhuma corresponde a uma vulnerabilidade real publicada. Os equipamentos também são fictícios — os modelos existem no mercado, mas combinações de fabricante/modelo/firmware aqui não descrevem nenhum ambiente real.

## Problema / Por que existe

Equipes de infraestrutura precisam saber quais equipamentos estão expostos a vulnerabilidades conhecidas. Fazer esse cruzamento à mão leva horas. Ordenar apenas pelo CVSS erra, porque o CVSS mede a gravidade técnica da falha, não o custo de perder aquele ativo específico. O `intelhub` faz o cruzamento em segundos e não deixa o CVSS decidir sozinho: combina a nota da falha com exposição de rede, criticidade do ativo e existência de workaround, e mostra a conta aberta na coluna Justificativa, para você auditar e discordar.

## O que faz

Lê um JSON de inventário e um JSON de CVEs, casa fabricante, modelo e faixa de versão de firmware, calcula uma pontuação de risco por par (equipamento, CVE) e grava um HTML autocontido com o ranking agrupado por ativo. Cada linha mostra CVE, fabricante, modelo, firmware, criticidade, exposição de rede, risco, justificativa e recomendação.

## Stack

- Python 3.10 ou superior
- Zero dependências de runtime (apenas stdlib)
- pytest para a suíte de testes
- Dados de entrada em JSON (inventário e base de CVEs fictícios)
- Saída: arquivo HTML autocontido, sem dependência de caminhos absolutos

## Como funciona

Quatro etapas, uma por módulo:

```
inventario.json ──┐
                  ├─► cruzamento ─► priorizacao ─► relatorio ─► .html
cves.json ────────┘
```

| Módulo | Responsabilidade |
|--------|------------------|
| `inventario.py` | Lê e valida o inventário: fabricante, modelo, firmware, criticidade, exposição de rede |
| `cvedb.py` | Carrega a base de CVEs e compara versão por aritmética, alinhando tuplas com zeros |
| `cruzamento.py` | Casa cada CVE com o equipamento por fabricante + modelo + faixa de versão afetada |
| `priorizacao.py` | Calcula o risco e devolve o ranking com justificativa e desempate determinístico |
| `relatorio.py` | Gera o HTML autocontido, agrupado por ativo, com escape de HTML |
| `cli.py` | Interface de linha de comando |

### Comparação de versão

Comparar firmware é aritmética, não comparação de texto. Um `str` diria que `"9.10" < "9.2"`, porque `1 < 2` no primeiro caractere divergente. O `intelhub` normaliza antes de comparar, preenchendo com zeros à direita:

| Firmware | versus | Resultado |
|----------|---------|-----------|
| `9` | `9.2.0` | mesma versão |
| `9.2` | `9.2.0` | mesma versão |
| `9.2.1` | `9.2.0` | mais novo |
| `9.10.0` | `9.2.0` | mais novo (não menor, como o `str` diria) |

Versão não numérica — `7.4.3-rc1`, `unknown` — levanta `VersaoInvalida` em vez de virar `0`, que compararia como anterior a tudo e geraria um falso positivo de exposição.

### Fórmula de risco

```
risco = cvss × fator_exposição + acréscimo_criticidade − (1.0 se houver workaround)
```

Limitado a `[0.0, 10.0]`, arredondado a 2 casas decimais.

| Peso | Valor | Significado |
|------|-------|-------------|
| `_EXPOSICAO["publico"]` | `1.1` | Equipamento alcançável da internet |
| `_EXPOSICAO["interno"]` | `1.0` | Só a rede interna alcança |
| `_CRITICIDADE["critica"]` | `+0.5` | Switch de core, firewall de borda, hypervisor |
| `_CRITICIDADE["alta"]` | `+0.3` | Servidor de aplicação, storage, DNS |
| `_CRITICIDADE["media"]` | `+0.1` | Ponto de acesso, sensor, câmera |
| `_CRITICIDADE["baixa"]` | `+0.0` | Console auxiliar, equipamento de borda |
| `_WORKAROUND` | `−1.0` | Fabricante já publicou correção |

A exposição de rede é um agravante de probabilidade — um scanner da internet alcança todo mundo — então é multiplicador. A criticidade é um agravante de consequência — perder um core derruba o prédio — então é acréscimo fixo. O workaround subtrai um ponto fixo porque não elimina a falha, apenas dá tempo até a janela de manutenção.

## Como rodar

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m pytest tests/
python -m intelhub cruzar --help
```

Saída do `cruzar --help`:

```
usage: intelhub cruzar [-h] --saida SAIDA inventario cves

positional arguments:
  inventario     Caminho do JSON do inventario.
  cves           Caminho do JSON de CVEs.

options:
  -h, --help     show this help message and exit
  --saida SAIDA  Caminho do HTML de saida.
```

Gerar o relatório:

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

Para rodar sem instalar nada, aponte o `PYTHONPATH` para `src`:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida relatorio.html
```

## Estrutura do projeto

```
threat-intel-dashboard/
├── src/intelhub/            # pacote Python
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py               # interface de linha de comando
│   ├── cruzamento.py        # casamento de equipamento com CVE
│   ├── cvedb.py             # base local de CVEs e comparacao de versoes
│   ├── inventario.py        # leitura e validacao do inventario
│   ├── priorizacao.py       # calculo de risco e ranking
│   └── relatorio.py         # geracao do HTML autocontido
├── dados/                   # inventario-equipamentos.json e cves-ficticias.json (ficticios)
├── docs/                    # metodo-de-priorizacao.md e como-funciona-o-cvss.md
├── exemplos/                # relatorio-exposicao.html gerado
├── tests/                   # 189 testes
├── tools/                   # gerar_exemplos.py, verificar_aceite.py, verificar_encoding.py, verificar_exemplo_limpo.py
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## Trade-offs e decisões

1. **Comparar firmware é aritmética, não texto.** Normalizar com zeros à direita evita que `"9.10"` seja lido como menor que `"9.2"`.
2. **Versão não numérica vira erro, não `0`.** `"7.4.3-rc1"` ou `"unknown"` levantam `VersaoInvalida`. Se virassem `0`, comparariam como anteriores a tudo e gerariam falso positivo de exposição.
3. **Multiplicar na exposição, somar na criticidade.** Exposição de rede é agravante de probabilidade (multiplicador 1.1 quando público). Criticidade é agravante de consequência (acréscimo fixo). O modelo reage diferente a um CVSS 9.1 num switch de core do que num ponto de acesso de andar.
4. **Desempate por (risco, cvss, id) para determinismo.** Dois itens com o mesmo risco aparecem sempre na mesma ordem, evitando diffs falsos no Git.
5. **Teto e piso do risco em [0.0, 10.0].** Sem o teto, um item apareceria com "11.3" numa coluna que vai até 10.
6. **Zero dependências de runtime.** Instalar um framework para aritmética sobre dados locais custaria instalação para todo mundo sem tornar o problema mais fácil.
7. **O campo `workaround` recusa strings não reconhecidas.** `"talvez"` gera erro em vez de adivinhação. Num relatório de segurança, um "está tudo bem" falso é pior que um erro barulhento.

## Limitações conhecidas

- **Não há probabilidade real de exploração.** Todo item exposto pesa igual, sem considerar histórico de ataque ou threat intel.
- **Não há dependência entre itens.** Três CVEs no mesmo switch sugerem três manutenções separadas, quando na prática é uma janela só.
- **O desconto de 1.0 por workaround é um valor arbitrário.** Está assim porque é auditável e discutível, não porque saiu de um modelo.
- **A base de CVEs é fictícia.** Para uso real, substitua `dados/cves-ficticias.json` por dados do NVD ou do seu fornecedor.
- **O inventário não tem campo de compensação.** Um ERP sem plano de continuidade e um ERP com redundância ativa recebem a mesma nota.

## Licença

MIT. Veja [`LICENSE`](LICENSE).

## Autor

Kelvin Oliveira
