# Como funciona o CVSS

O CVSS (Common Vulnerability Scoring System) é a escala que transforma uma
descrição de vulnerabilidade em um número entre 0 e 10. O `intelhub` usa esse
número como **ponto de partida** do ranking, nunca como veredito. Este
documento explica a escala, por que ela é útil e por que ela não decide o que
você ataca primeiro.

> A base de CVEs deste repositório é **inteiramente fictícia** (`CVE-2026-XXXXX`).
> As pontuações foram escolhidas para exercitar a priorização, não para
> reproduzir Vulnerable ou NVD.

## O que o número significa

| Faixa | Rótulo | Leitura prática |
|-------|--------|------------------|
| 9.0 – 10.0 | Crítica | Exploração remota trivial, ou impacto completo sem interação do usuário. |
| 7.0 – 8.9 | Alta | Exploração remota com alguma pré-condição, ou perda de confidencialidade/integidade ampla. |
| 4.0 – 6.9 | Média | Exige interação do usuário, ou-privilégios para a explore, ou o impacto é limitado. |
| 0.1 – 3.9 | Baixa | information leak limitado, ou vetor local ou físico. |
| 0.0 | Nenhuma | Sem impacto de segurança. |

O `intelhub` usa exatamente essas faixas para colorir as linhas do relatório
(`_classe_risco` em `src/intelhub/relatorio.py`).

## Os três grupos da métrica

O CVSS v3.1 (o padrão do `intelhub`) reduz a nota final a três grupos de
perguntas. Cada pergunta vira um componente com peso próprio.

### 1. Base (métrica base) — "o que a falha permite?"

| Métrica | Pergunta | Valores |
|---------|----------|---------|
| **AV** Attack Vector | Como se chega nela? | `N` rede, `A` adjacente, `L` local, `P` físico |
| **AC** Attack Complexity | Quanto trabalho para explorá-la? | `L` baixo, `H` alto |
| **PR** Privileges Required | Que permissão o atacante já tem? | `N` nenhuma, `L` baixa, `H` alta |
| **UI** User Interaction | Alguém precisa clicar em algo? | `N` não, `R` sim |
| **C** / **I** / **A** | O que quebra: sigilo, integridade, disponibilidade? | `N` nenhum, `L` baixo, `H` alto |

O vetor completo é a string que aparece no campo `vector` de cada CVE:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Que é o famoso `9.8` — rede, sem privilégio, sem clique, sem escopo alterado,
com as três consequências no máximo.

### 2. Temporal — "quanto tempo isso está exposto?"

Aparece no CVSS v4.0 e é justamente onde a matemática faz o trabalho sujo:
quando o fornecedor publica uma correção, a **exploitabilidade cai de 1.0 para
0.94**, o **nível de remediamento sobe de 0.87 para 0.95** e a pontuação
despenca. Uma vulnerabilidade de 9.8 sem correção há seis meses e uma de 9.8
corrigida ontem podem diferir em poucos pontos entre si, mesmo tendo o mesmo
número base. É por isso que "9.8" sozinho não é um plano de ação.

### 3. Ambiental (métrica ambiental) — "no meu ambiente, importa?"

É a métrica que responde à pergunta que o CVSS base não responde: *isso aqui
importa para mim?* Você declara Critical Assets, escolhe o valor real de C/I/A
para o seu cenário e pode penalizar ou reforçar. Uma vulnerabilidade que exige
`PR:H` (privilégio alto) numa box de borda pode ser menos perigosa que uma
`PR:N` que expõe a segmentação inteira. Essa métrica é exatamente a ideia que o
`intelhub` implementa de forma simplificada — veja
[metodo-de-priorizacao.md](metodo-de-priorizacao.md).

## Como a nota é calculada

O CVSS v3.1 usa a fórmula do fator de impacto com expoente. Com o conteúdo mais
frequente, `C=I=A=H` e escopo inalterado, a fórmula se reduz ao produto linear
dos pesos:

```
Impacto ≈ 1 − [(1 − C) × (1 − I) × (1 − A)]
BaseScore = Roundup(mínimo[
    (Impacto × Exploitabilidade),
    (Impacto × Exploitabilidade) − 10,
])
```

O arredondamento para cima (`Roundup`, uma casa decimal) é o que produz o
famigerado `9.8` em vez de `9.75`.

E a exploitabilidade depende do vetor:

```
Exploitabilidade = 8.22 × AV × AC × PR × UI
```

Repare no quanto o desenho do vetor pesa. Do pior para o melhor, só o vetor
`AV` move o resultado:

- `AV:L` (local) = 0.55
- `AV:A` (adjacente) = 0.62
- `AV:N` (rede) = 0.85

Sozinho, trocar `AV:P` por `AV:N` — o vetor mais grave — tira quase três pontos.
É por isso que uma falha que "só" é explorável na rede local, mas roda num
serviço com cara de rede (VPN concentrador, appliance de borda), merece o
tratamento de `AV:N`.

## Por que CVSS sozinho não decide prioridade

CVSS mede **gravidade técnica da falha**, não **custo de atacar aquele ativo**.
São eixos diferentes, e o ranking errado vem de tratar um como o outro. Quatro
casos concretos, que a base deste repositório reproduz:

### 1. Mesmo CVSS, riscos opostos

Dois CVE com `CVSS 9.1`, ambos remotos:

- um deles está num **switch de core**, `criticidade: crítica`, `exposicao_red: publico`
- o outro está num **ponto de acesso de andar**, `criticidade: baixa`, `exposicao_red: interno`

O primeiro vale `9.1 × 1.1 + 0.5 = 10.51 → 10.0` no `intelhub`.
O segundo vale `9.1 × 1.0 + 0.0 = 9.1`. A diferença de 0.9 pontos no ranking
corresponde a diferença real: derrubar o core derruba o prédio inteiro.

### 2. CVSS alto, sem caminho

Um firmware de switch aceita um pacote malformado, mas **só** a partir da rede
de gerência, nunca da internet. O CVSS base é 7.5. Multiplicar por 1.0 porque
a exposição é interna é o correto — mas isso significa que o item só é
explorável a partir de um salto que já é monitorado. Ele não pode ser o primeiro
da fila de um fim de semana.

### 3. Criticidade alta empurra item médio

Um appliance de firewall com firmware de vanguarda (`CVSS 5.3`, que exige
autenticação) e `criticidade: crítica`, exposto à internet, vale
`5.3 × 1.1 + 0.5 = 6.33`. Fica acima de um ERP com `CVSS 7.5`, exposição
interna e criticidade média, que vale `7.5 × 1.0 + 0.1 = 7.6`… **não**. Aqui
está o ponto: mesmo com o empurrão de criticidade, o ERP ainda ganha. Mas se
o ERP fosse `CVSS 5.9`, teria `6.0` e perderia. Um modelo que só lê "o firewall
é mais importante" erra; um modelo que só lê "CVSS manda" erra do outro lado.

### 4. Workaround publicado muda o dia

Quando o fabricante publica uma correção **antes** de você conseguir agendar a
janela de manutenção, o risco prático cai muito. O `intelhub` desconta 1.0 ponto
de todo item com `workaround: true`. Não zera o risco — o item continua no
relatório — mas ele desce da frente da fila, que é onde a decisão real acontece.

## O que fazer com essa leitura

A tabela do relatório não esconde nenhum desses fatores: cada linha mostra
`CVSS`, `exposicao`, `criticidade`, se há `workaround`, e a **Justificativa**
que é literalmente a conta feita. Você pode auditar o número no relatório,
recalcular à mão e discordar.

O ranking é um ponto de partida para a conversa depriorização, não a conversa.
O que decide o que você conserta primeiro é o que a pontuação não sabe: existe
compensação? O fornecedor já avisou? Dá para testar em laboratório antes? A
conversa com quem opera o ativo vale mais que a última casa decimal.
