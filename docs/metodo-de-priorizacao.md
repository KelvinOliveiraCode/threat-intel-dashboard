# Método de priorização

O `intelhub` responde a uma pergunta que o CVSS não responde: **com tudo que
está exposto na minha rede, o que eu conserto primeiro?**

A resposta não pode ser "o CVE com a nota mais alta", porque a nota_cvss mede a
gravidade técnica da falha, não o custo de perder aquele ativo específico. Este
documento descreve a fórmula, mostra a conta linha a linha e expõe onde ela é
simples demais — porque um número que você não consegue auditar não serve para
justificar uma janela de manutenção.

A implementação está em `src/intelhub/priorizacao.py`.

## A fórmula

```
risco = cvss
      × fator_exposição_de_rede
      + acréscimo_de_criticidade_do_ativo
      − 1.0 se existe workaround publicado

risco = limitado ao intervalo [0.0, 10.0], arredondado a 2 casas
```

Quatro pesos, todos em `priorizacao.py`:

| Peso | Valor | Significado |
|------|-------|-------------|
| `_EXPOSICAO["publico"]` | `1.1` | O equipamento é alcançável da internet |
| `_EXPOSICAO["interno"]` | `1.0` | Só a rede interna alcança |
| `_CRITICIDADE["critica"]` | `+0.5` | Switch de core, firewall de borda, hypervisor |
| `_CRITICIDADE["alta"]` | `+0.3` | Servidor de aplicação, storage, DNS |
| `_CRITICIDADE["media"]` | `+0.1` | Ponto de acesso, sensor, câmera |
| `_CRITICIDADE["baixa"]` | `+0.0` | Console auxiliar, equipamento de borda |
| `_WORKAROUND` | `−1.0` | O fabricante já publicou correção |

## Por que multiplicar exposição e somar criticidade

A escolha de OperationsResearch é multiplicar na exposição e somar na
criticidade, e a razão importa.

Exposição de rede é um **agravante de probabilidade**: um equipamento na
internet é alcançado por qualquer scanner da Terra, todo dia. Isso eleva o
risco na proporção — 10% — em vez de somar um valor fixo. Por isso é
multiplicador.

Criticidade do ativo é um **agravante de consequência**: perder um core
derruba todos os andares; perder um ponto de acesso custa um ponto de acesso.
Isso não escala com a nota da falha, é um peso próprio. Por isso é acréscimo.

Workaround é um **alívio temporário**: não elimina a falha, dá um caminho
para respirar até a janela de manutenção. Por isso subtrai um valor fixo em
vez de multiplicar — se multiplicasse, um item com `cvss 2.0` e workaround
cairia para `1.0` e quase sumiria do ranking, mas a falha continua lá.

## A conta aberta

O relatório não mostra só o resultado. A coluna **Justificativa** é a conta
feita, e ela sai do código, não de um texto escrito à mão:

```
CVSS 10.0; exposicao 1.1x; criticidade +0.3
```

Dá para recalcular de cabeça e bater. `10.0 × 1.1 + 0.3 = 11.3`, limitado a
10.0 pelo teto. Quando o número bate com a conta, o número é confiável; quando
não bate, é bug — e o teste `tests/test_relatorio_cli.py` exige que o total do
resumo corresponda ao ranking real justamente para pegar esse tipo de deriva.

## Três exemplos da base fictícia

A base tem 13 equipamentos e 81 CVEs fictícios. Os três casos abaixo saíram
do ranking real gerado — os mesmos números que `exemplos/relatorio-exposicao.html`
mostra.

### Caso 1 — ativo exposto no topo, sem correção

```
Palo Alto PA-3220   fw 10.1.0   criticidade alta    exposição público
CVE-2026-8001       cvss 10.0   workaround: não
```

```
10.0 × 1.1 + 0.3 = 11.3 → teto de 10.0 → 10.00
```

O teto de 10.0 não é detalhe: ele existe porque a escala é um intervalo
fechado. Sem ele, um item poderia aparecer com "11.3" numa coluna que vai até
10, e qualquer regra externa que leia essa coluna quebraria.

### Caso 2 — ativo de borda, quase o fim da fila

```
Ubiquiti EdgeRouter ER-12   fw 2.0.9   criticidade baixa   exposição interno
CVE-2026-9102               cvss 8.1    workaround: não
```

```
8.1 × 1.0 + 0.0 = 8.10
```

CVSS 8.1 não é pouco. Mas o equipamento é de criticidade baixa e só a rede
interna alcança, então os dois agravantes somam zero e o número desce para
8.10 — abaixo de seis itens de switch e firewall. Note que a justificativa
diz só `CVSS 8.1`: os dois pesos entraram como `1.0` e `0.0`, que o código
omite por serem o caso neutro. Uma justificativa mais curta aqui significa
"nada empurrou para cima", não "nada foi avaliado".

### Caso 3 — com workaround

```
MikroTik CCR2004        fw 7.4.1   criticidade média   exposição público
CVE-2026-6002           cvss 8.6    workaround: sim
```

```
8.6 × 1.1 + 0.1 − 1.0 = 8.56
```

O −1.0 tira o item da frente da fila, mas ele continua no relatório com
a recomendação "aplicar o workaround publicado e agendar a atualização". O
desconto não é perdão — é uma janela para agir antes da janela de manutenção.

## Ordenação e desempate

O ranking ordena por três chaves, nesta ordem:

```python
key = (risco, cvss, id_da_cve)
reverse = True
```

O desempate por `cvss` e depois por `id` da CVE existe por um motivo prático:
**determinismo**. Dois itens com o mesmo risco precisam aparecer sempre na
mesma ordem, senão o relatório muda entre execuções, o diff do Git enche de
mudança falsa e ninguém confia no versionamento. O `tools/verificar_aceite.py`
checa exatamente isso.

## Onde este método é simples demais

Um método honesto diz onde ele falha. Este tem quatro limites conhecidos:

### 1. Não há probabilidade real

O ranking trata toda exposição pública como igualmente provável. Não há
modelo de quem está atacando aquele IP, nem histórico. Em um ambiente
real, um `/24` inteiro na internet não tem a mesma probabilidade de ataque
de um IP específico que acabou de aparecer em um threat feed.

### 2. Não há dependência entre itens

Se corrigir um CVE exige reiniciar o mesmo switch onde estão os outros 12,
o ranking não sabe. Ele vai sugerir consertar os três primeiros "agora" e o
operador vai descobrir sozinho que são a mesma janela de manutenção. Um
método de segunda geração agruparia por "janela de mudança", não por nota.

### 3. O desconto de 1.0 é arbitrário

Ponto fixo, não derivado de nada. Podia ser 0.5 ou 2.0 e a lógica continuaria
"correta" — só mudaria a ordem. Está assim porque é **auditável e discutível**,
que vale mais do que um número precise e não justificável. Quem quiser mudar,
muda uma constante com nome próprio e o relatório inteiro reflete na
hora seguinte.

### 4. Compensação é ausência de informação

O inventário não tem campo "existe plano de continuidade?". Um ERP sem
compensação e um ERP com redundância ativa recebem a mesma nota. Se a sua
organização tem esse dado, ele entra no inventário — e aí vale estender
`priorizacao.py`, porque a fórmula está isolada em uma função com quatro
pesos nomeados.

## Como trocar a fórmula

`_EXPOSICAO`, `_CRITICIDADE` e `_WORKAROUND` são dicionários e constantes no
topo do módulo. Adicionar um fator novo é:

1. Definir a constante ou o dicionário com nome próprio.
2. Aplicar em `calcular_risco`.
3. Adicionar a parcela correspondente na lista `partes`, senão o número muda
   e a justificativa não explica por quê — e aí a justificativa mente.
4. Cobrir com teste em `tests/test_priorizacao.py`, incluindo o caso de
   limite do teto e do piso.

O passo 3 não é burocracia. Uma justificativa que não bate com a conta é
pior que nenhuma justificativa: ela treina o leitor a não conferir.
