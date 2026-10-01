# intelhub (English)

Cross-reference a local equipment inventory against an embedded vulnerability
database and produce a **risk-prioritized exposure report** as a
self-contained HTML file.

Portuguese version: [`README.md`](README.md)

> **All data in this repository is fictional.** The 81 CVEs use the
> `CVE-2026-XXXXX` pattern and were invented to exercise prioritization. None
> matches a real published vulnerability. The equipment is fictional too — the
> models exist on the market, but the manufacturer/model/firmware combinations
> here describe no real environment.

## The problem it solves

Clients and infrastructure teams ask for this cross-reference constantly:
"which of these 300 devices are affected by a known flaw?" The manual answer
takes hours, and the wrong answer happens whenever someone sorts the queue by
CVSS alone.

`intelhub` does the cross-reference in seconds and — the important part —
**does not let CVSS decide on its own**. It combines the flaw's score with
network exposure, asset criticality and whether a workaround exists, and shows
the open arithmetic in the *Justificativa* column so you can audit it and
disagree.

## Install

Zero runtime dependencies. Python 3.10 or newer.

```powershell
git clone <repository-url>
cd threat-intel-dashboard
pip install -e ".[dev]"
```

## Usage

```powershell
python -m intelhub cruzar dados/inventario-equipamentos.json dados/cves-ficticias.json --saida exemplos/relatorio-exposicao.html
```

Actual output:

```
Equipamentos inventariados: 13
CVEs na base: 81
Exposicoes encontradas: 73
Relatorio gravado em: exemplos\relatorio-exposicao.html
```

A sample report is committed at
[`exemplos/relatorio-exposicao.html`](exemplos/relatorio-exposicao.html).

## How it works

Four steps, one per module:

```
inventory.json ──┐
                ├─► cross-reference ─► prioritization ─► report ─► .html
cves.json ──────┘
```

| Module | Responsibility |
|--------|----------------|
| `inventario.py` | Reads and validates the inventory: vendor, model, firmware, criticality, exposure |
| `cvedb.py` | Loads the CVE database and compares versions with zero-padding alignment |
| `cruzamento.py` | Matches a CVE to a device by vendor + model + affected range |
| `priorizacao.py` | Computes risk and returns the ranking with a justification |
| `relatorio.py` | Generates the self-contained HTML, grouped by asset |
| `cli.py` | The command line |

Module names stay in Portuguese to match the portfolio; the domain vocabulary
is the same in both languages (`fabricante`/`manufacturer`, `modelo`/`model`,
`firmware`, `criticidade`/`criticality`).

### The version-comparison detail

Comparing firmware is arithmetic, not string comparison. A `str` says
`"9.10" < "9.2"`, because `1 < 2` at the first differing character.

`intelhub` normalizes before comparing, padding on the right with zeros:

| Firmware | versus | Result |
|----------|--------|--------|
| `9` | `9.2.0` | same version |
| `9.2` | `9.2.0` | same version |
| `9.2.1` | `9.2.0` | newer |
| `9.10.0` | `9.2.0` | newer (not older, as `str` would say) |

A non-numeric version — `7.4.3-rc1`, `unknown` — raises `VersaoInvalida`
instead of silently becoming `0`, which would compare as older than everything
and produce a false exposure.

### The risk formula

```
risk = cvss x exposure_factor + criticality_bonus - (1.0 if a workaround exists)
```

Clamped to `[0.0, 10.0]`. The full method and its limits are in
[`docs/metodo-de-priorizacao.md`](docs/metodo-de-priorizacao.md) (Portuguese),
and what CVSS, the attack vector and why the score alone does not decide
priority are in [`docs/como-funciona-o-cvss.md`](docs/como-funciona-o-cvss.md)
(Portuguese).

## Data formats

**`dados/inventario-equipamentos.json`** — equipment list. Keys stay in
Portuguese: `fabricante`, `modelo`, `firmware`, `criticidade`, `exposicao_red`.

`criticidade` accepts `critica`, `alta`, `media`, `baixa`.
`exposicao_red` accepts `publico`, `interno`.

**`dados/cves-ficticias.json`** — fictional vulnerability list. Keys follow the
CVE schema in English: `id`, `description`, `cvss`, `vector`,
`affected_version`, `manufacturer`, `model`, `workaround`.

`affected_version` accepts a single version (`15.2.4`) or a range
(`8.7.0 - 8.7.1`). `workaround` indicates whether the vendor has published a
fix. The CVE record uses `model` because that is the name the CVE format
already uses; the internal modules use `modelo`, like the rest of the codebase.

## Library use

```python
from intelhub.cruzamento import cruzar
from intelhub.cvedb import carregar_cves
from intelhub.inventario import carregar_inventario
from intelhub.priorizacao import rankear
from intelhub.relatorio import gerar_relatorio_html

inventory = carregar_inventario("dados/inventario-equipamentos.json")
cves = carregar_cves("dados/cves-ficticias.json")

ranking = rankear(cruzar(inventory, cves))

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

## Tests

```powershell
python -m pytest tests/ -v
```

134 tests, 96% coverage. They cover version comparison, range matching, the
formula's clamp at both ends, HTML escaping (the report takes text from a file
and must never let `<script>` through raw), deterministic ordering, and the
whole CLI.

Checks the suite alone does not cover:

```powershell
python tools/verificar_aceite.py    # 12 exposed, 1 clean, ordering holds
python tools/verificar_encoding.py  # no corrupted characters
python tools/gerar_exemplos.py      # regenerates the example deterministically
```

`verificar_aceite.py` includes a **clean** device — the `FortiGate 60F` on
firmware `7.4.3`, above the affected range. Without a negative case, a filter
that returned everything would still pass.

## Structure

```
threat-intel-dashboard/
├── src/intelhub/            # the package
├── dados/                   # inventory and fictional CVE database
├── docs/                    # CVSS and prioritization method (Portuguese)
├── exemplos/                # generated HTML report
├── tests/                   # 134 tests
└── tools/                   # data generator and verification scripts
```

## Limitations

Stated up front, because a security report that hides its own reach is worth
nothing:

- **No exploitation probability.** Every exposed item weighs the same, with no
  attack history or threat intel input.
- **No dependency between items.** Three CVEs on one switch still suggest three
  separate maintenance windows, when in practice it is one.
- **The 1.0 workaround discount is arbitrary.** It is a named constant because
  it is auditable and arguable, not because it came out of a model.
- **The database is fictional.** For real use, replace
  `dados/cves-ficticias.json` with NVD or vendor data and reweight the context
  factors.

## License

MIT.
