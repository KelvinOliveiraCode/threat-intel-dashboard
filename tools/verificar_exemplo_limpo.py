#!/usr/bin/env python
"""Verifica que o relatorio de exemplo nao carrega caminho da maquina.

Check that the committed example report carries no local filesystem paths.

Um relatorio que vai para commit e para issue de ticket nao pode conter o
caminho de quem o gerou: estraga a revisao do diff e ainda entrega informacao
da maquina de desenvolvimento de qualquer pessoa que clona o repositorio.

Exit code 0 = nenhum caminho local encontrado.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Marcadores de caminho absoluto de Windows, home de Unix e perfil de usuario.
MARCAS = ("C:\\Users", "C:/Users", "/Users/", "/home/", "C:\\", "D:\\", "AppData")

ALVO = Path(__file__).resolve().parent.parent / "exemplos" / "relatorio-exposicao.html"


def main() -> int:
    """Confere o exemplo versionado.

    Check the committed example.

    Returns:
        0 se o relatorio estiver limpo, 1 se houver caminho local.
    """
    if not ALVO.exists():
        print(f"erro: exemplo ausente em {ALVO}")
        return 1

    texto = ALVO.read_text(encoding="utf-8")
    achados = [m for m in MARCAS if m in texto]

    if achados:
        print("caminho de maquina encontrado no exemplo:")
        for marca in achados:
            for linha in texto.splitlines():
                if marca in linha:
                    print(f"  [{marca}] {linha.strip()[:160]}")
        return 1

    print(f"exemplo limpo: nenhum caminho local em {ALVO.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
