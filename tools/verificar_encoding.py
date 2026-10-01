"""Confere encoding dos arquivos do repositorio.

Check the encoding of every file in the repository.

Este gate e mais largo que o dos outros projetos deste portfolio. Aqui a
preocupacao nao e apenas caractere de substituicao: e acento dentro de
literal. Ja aconteceu aqui de o codigo escrever a palavra ``cratica`` (com a)
enquanto o dado escrevia ``critica`` (com i), e a comparacao falhava em tempo
de execucao. Num terminal que mostra acento como se fosse ASCII, isso passa
despercebido numa revisao.

Por isso: em ``.py``, ``.json``, ``.yaml``, ``.yml`` e ``.toml``, **todo**
caractere acima de U+007F e erro. Markdown pode ter acento, porque portugues
escrito leva acento e documento sem acento fica pior.

Um U+FFFD e um caractere de substituicao, sinal de escrita corrompida.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Raiz do repositorio.
RAIZ = Path(__file__).resolve().parent.parent

#: Extensoes que devem ser ASCII puro. Acento em codigo ou em dado vira
#: comparacao que falha em tempo de execucao.
ASCII_PURO = {".py", ".json", ".yaml", ".yml", ".toml", ".cfg", ".txt"}

#: Extensoes que podem ter acento.
COM_ACENTO = {".md"}

#: Diretorios ignorados.
IGNORADOS = {
    ".git", ".pytest_cache", "__pycache__", "htmlcov", ".venv", "venv",
    "build", "dist", ".coverage", "coverage.xml",
}

#: Intervalo de ideogramas CJK, que nunca pertence a este repositorio.
CJK = range(0x3000, 0x9FFF + 1)

#: Caractere de substituicao.
SUBSTITUICAO = 0xFFFD


def varrer(raiz: Path = RAIZ) -> list[tuple[str, int, str]]:
    """Procura arquivo com caractere que nao deveria estar la.

    Find files holding a character that should not be there.

    Args:
        raiz: Diretorio a varrer.

    Returns:
        Lista de ``(caminho, linha, motivo)``.
    """
    problemas: list[tuple[str, int, str]] = []
    for caminho in sorted(raiz.rglob("*")):
        if not caminho.is_file():
            continue
        if any(parte in IGNORADOS for parte in caminho.parts):
            continue
        extensao = caminho.suffix.lower()
        if extensao not in ASCII_PURO and extensao not in COM_ACENTO:
            continue
        try:
            texto = caminho.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            problemas.append((
                str(caminho.relative_to(raiz)), 0,
                f"nao decodifica como UTF-8: {exc}",
            ))
            continue
        for numero, linha in enumerate(texto.splitlines(), 1):
            for caractere in linha:
                ponto = ord(caractere)
                if ponto == SUBSTITUICAO:
                    problemas.append((
                        str(caminho.relative_to(raiz)), numero,
                        "caractere de substituicao U+FFFD",
                    ))
                    break
                if ponto in CJK:
                    problemas.append((
                        str(caminho.relative_to(raiz)), numero,
                        f"ideograma CJK U+{ponto:04X}",
                    ))
                    break
                if ponto > 127 and extensao in ASCII_PURO:
                    problemas.append((
                        str(caminho.relative_to(raiz)), numero,
                        f"caractere nao-ASCII em arquivo de codigo: "
                        f"U+{ponto:04X} ({caractere!r})",
                    ))
                    break
    return problemas


def main() -> int:
    """Executa a varredura e reporta.

    Run the sweep and report.
    """
    problemas = varrer()
    if not problemas:
        print("encoding ok: nenhum U+FFFD, nenhum ideograma CJK e nenhum "
              "caractere nao-ASCII em codigo ou dado")
        return 0
    print(f"encoding FALHOU: {len(problemas)} ocorrencia(s)")
    for caminho, linha, motivo in problemas:
        onde = f"{caminho}:{linha}" if linha else caminho
        print(f"  {onde}: {motivo}")
    return 1


if __name__ == "__main__":
    sys.exit(main())