"""Gera o arquivo de CVEs ficticias.

Generate the synthetic CVE file.

O arquivo de CVE nao existe no repositorio e e obrigatorio pela especificacao:
60 ou mais vulnerabilidades sinteticas. Este script escreve o arquivo a partir
de uma lista compacta, para que a origem dos numeros seja uma linha de codigo e
nao um bloco de JSON digitado a mao.

Todas as CVEs seguem o formato ``CVE-2026-XXXXX``. Nenhum dado real de scanner
entrou aqui, e o validador recusa qualquer id fora desse formato.

Uso: python tools/gerar_cves.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DESTINO = RAIZ / "dados" / "cves-ficticias.json"

#: (id, fabricante, modelo, faixa afetada, cvss, vector, workaround)
#: A faixa e escrita de forma compacta; a ordem importa e e conferida por
#: teste.
LINHAS: list[tuple[str, str, str, str, float, str, bool]] = [
    # ---- Fortinet FortiGate 60F, firmware 7.4.1 no inventario ----
    ("CVE-2026-1001", "Fortinet", "FortiGate 60F", "7.0.0 - 7.4.1", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
    ("CVE-2026-1002", "Fortinet", "FortiGate 60F", "7.4.0 - 7.4.1", 8.1,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-1003", "Fortinet", "FortiGate 60F", "7.2.0 - 7.4.1", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", True),
    ("CVE-2026-1004", "Fortinet", "FortiGate 60F", "7.4.1", 9.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", False),
    ("CVE-2026-1005", "Fortinet", "FortiGate 60F", "6.4.0 - 7.4.1", 6.5,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-1006", "Fortinet", "FortiGate 60F", "7.4.0 - 7.4.2", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", True),
    # ---- Cisco Catalyst 2960, firmware 15.2.4 ----
    ("CVE-2026-2001", "Cisco", "Catalyst 2960", "15.0.0 - 15.2.4", 8.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-2002", "Cisco", "Catalyst 2960", "15.2.0 - 15.2.4", 7.8,
     "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", False),
    ("CVE-2026-2003", "Cisco", "Catalyst 2960", "15.2.4", 9.0,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", False),
    ("CVE-2026-2004", "Cisco", "Catalyst 2960", "15.0.0 - 15.1.9", 6.4,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:P/I:N/A:N", True),
    ("CVE-2026-2005", "Cisco", "Catalyst 2960", "15.1.0 - 15.2.4", 4.3,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    ("CVE-2026-2006", "Cisco", "Catalyst 2960", "15.2.0 - 15.2.3", 5.9,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", True),
    # ---- Juniper EX3400, firmware 12.3.1 ----
    ("CVE-2026-3001", "Juniper", "EX3400", "12.3.0 - 12.3.1", 9.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", False),
    ("CVE-2026-3002", "Juniper", "EX3400", "12.0.0 - 12.3.1", 7.7,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-3003", "Juniper", "EX3400", "12.3.1", 8.2,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", False),
    ("CVE-2026-3004", "Juniper", "EX3400", "11.4.0 - 12.3.1", 6.1,
     "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-3005", "Juniper", "EX3400", "12.3.0 - 12.3.2", 5.0,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:P/I:N/A:N", True),
    ("CVE-2026-3006", "Juniper", "EX3400", "12.3.1", 4.7,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- Aruba AP-315, firmware 8.7.1 ----
    ("CVE-2026-4001", "Aruba", "AP-315", "8.6.0 - 8.7.1", 8.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", False),
    ("CVE-2026-4002", "Aruba", "AP-315", "8.7.1", 7.4,
     "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", True),
    ("CVE-2026-4003", "Aruba", "AP-315", "8.0.0 - 8.7.1", 6.2,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-4004", "Aruba", "AP-315", "8.7.0 - 8.7.1", 5.3,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", True),
    ("CVE-2026-4005", "Aruba", "AP-315", "8.7.1", 4.0,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- NetApp FAS2700, firmware 9.8.0 ----
    ("CVE-2026-5001", "NetApp", "FAS2700", "9.8.0 - 9.8.4", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", False),
    ("CVE-2026-5002", "NetApp", "FAS2700", "9.6.0 - 9.8.0", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-5003", "NetApp", "FAS2700", "9.8.0", 9.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", False),
    ("CVE-2026-5004", "NetApp", "FAS2700", "9.4.0 - 9.8.0", 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", True),
    ("CVE-2026-5005", "NetApp", "FAS2700", "9.7.0 - 9.8.0", 6.8,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-5006", "NetApp", "FAS2700", "9.8.0 - 9.8.1", 5.9,
     "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-5007", "NetApp", "FAS2700", "9.8.0", 4.9,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- MikroTik CCR2004, firmware 7.4.1 ----
    ("CVE-2026-6001", "MikroTik", "CCR2004", "7.0.0 - 7.4.1", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
    ("CVE-2026-6002", "MikroTik", "CCR2004", "7.4.0 - 7.4.1", 8.6,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", True),
    ("CVE-2026-6003", "MikroTik", "CCR2004", "7.4.1", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", True),
    ("CVE-2026-6004", "MikroTik", "CCR2004", "6.49.0 - 7.4.1", 6.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", False),
    ("CVE-2026-6005", "MikroTik", "CCR2004", "7.2.0 - 7.4.1", 4.7,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- Dell PowerEdge R750, firmware 2.3.1 ----
    ("CVE-2026-7001", "Dell", "PowerEdge R750", "2.0.0 - 2.3.1", 8.2,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", False),
    ("CVE-2026-7002", "Dell", "PowerEdge R750", "2.3.0 - 2.3.1", 7.2,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-7003", "Dell", "PowerEdge R750", "2.3.1", 6.0,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:P/I:P/A:N", True),
    ("CVE-2026-7004", "Dell", "PowerEdge R750", "1.5.0 - 2.3.1", 4.9,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-7005", "Dell", "PowerEdge R750", "2.3.1", 3.9,
     "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", True),
    # ---- Palo Alto PA-3220, firmware 10.1.0 ----
    ("CVE-2026-8001", "Palo Alto", "PA-3220", "10.0.0 - 10.1.0", 10.0,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", False),
    ("CVE-2026-8002", "Palo Alto", "PA-3220", "10.1.0", 9.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
    ("CVE-2026-8003", "Palo Alto", "PA-3220", "9.1.0 - 10.1.0", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-8004", "Palo Alto", "PA-3220", "10.0.0 - 10.1.1", 6.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-8005", "Palo Alto", "PA-3220", "10.1.0", 5.4,
     "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-8006", "Palo Alto", "PA-3220", "10.1.0 - 10.1.0", 4.3,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- Cisco Catalyst 2960, faixa adicional para volumetria ----
    ("CVE-2026-2007", "Cisco", "Catalyst 2960", "15.0.0 - 15.2.4", 5.8,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", True),
    ("CVE-2026-2008", "Cisco", "Catalyst 2960", "15.2.0 - 15.2.4", 4.0,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", True),
    ("CVE-2026-2009", "Cisco", "Catalyst 2960", "15.2.4", 3.1,
     "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", True),
    # ---- Juniper EX3400, faixa adicional ----
    ("CVE-2026-3007", "Juniper", "EX3400", "12.0.0 - 12.3.1", 5.4,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-3008", "Juniper", "EX3400", "12.3.0 - 12.3.1", 4.4,
     "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", True),
    ("CVE-2026-3009", "Juniper", "EX3400", "12.1.0 - 12.3.1", 3.5,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", True),
    # ---- Fortinet FortiGate 60F, faixa adicional ----
    ("CVE-2026-1007", "Fortinet", "FortiGate 60F", "7.4.0 - 7.4.1", 4.3,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    ("CVE-2026-1008", "Fortinet", "FortiGate 60F", "7.3.0 - 7.4.1", 3.7,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", True),
    ("CVE-2026-1009", "Fortinet", "FortiGate 60F", "7.4.1", 5.0,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", True),
    # ---- NetApp FAS2700, faixa adicional ----
    ("CVE-2026-5008", "NetApp", "FAS2700", "9.7.0 - 9.8.0", 4.3,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    ("CVE-2026-5009", "NetApp", "FAS2700", "9.8.0 - 9.8.2", 3.3,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", True),
    # ---- Palo Alto PA-3220, faixa adicional ----
    ("CVE-2026-8007", "Palo Alto", "PA-3220", "10.0.0 - 10.1.0", 3.9,
     "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-8008", "Palo Alto", "PA-3220", "10.1.0", 4.4,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N", True),
    # ---- MikroTik CCR2004, faixa adicional ----
    ("CVE-2026-6006", "MikroTik", "CCR2004", "7.4.0 - 7.4.1", 3.1,
     "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-6007", "MikroTik", "CCR2004", "7.1.0 - 7.4.1", 4.4,
     "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- Aruba AP-315, faixa adicional ----
    ("CVE-2026-4006", "Aruba", "AP-315", "8.6.0 - 8.7.1", 3.3,
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", True),
    ("CVE-2026-4007", "Aruba", "AP-315", "8.5.0 - 8.7.1", 4.0,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", True),
    # ---- Dell PowerEdge R750, faixa adicional ----
    ("CVE-2026-7006", "Dell", "PowerEdge R750", "2.2.0 - 2.3.1", 3.1,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", True),
    ("CVE-2026-7007", "Dell", "PowerEdge R750", "2.0.0 - 2.3.1", 4.0,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", True),
    # ---- HP Aruba 2930M: fora de qualquer faixa do firmware 16.0.1 ----
    ("CVE-2026-9001", "HP", "Aruba 2930M", "16.10.0 - 16.10.9", 7.4,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-9002", "HP", "Aruba 2930M", "16.0.0 - 16.0.1", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    ("CVE-2026-9003", "HP", "Aruba 2930M", "16.10.0 - 16.10.5", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", False),
    # ---- Ubiquiti EdgeRouter ER-12: firmware 2.0.9, CVEs acima ----
    ("CVE-2026-9101", "Ubiquiti", "EdgeRouter ER-12", "2.0.0 - 2.0.9", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-9102", "Ubiquiti", "EdgeRouter ER-12", "2.0.9", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", False),
    ("CVE-2026-9103", "Ubiquiti", "EdgeRouter ER-12", "2.1.0 - 2.1.4", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", True),
    # ---- Lenovo ThinkSystem SR650: firmware 1.7.4 ----
    ("CVE-2026-9201", "Lenovo", "ThinkSystem SR650", "1.7.0 - 1.7.4", 7.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", True),
    ("CVE-2026-9202", "Lenovo", "ThinkSystem SR650", "1.7.4", 8.8,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", False),
    ("CVE-2026-9203", "Lenovo", "ThinkSystem SR650", "1.6.0 - 1.7.4", 6.2,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    # ---- WatchGuard Firebox T35: firmware 12.4.0 ----
    ("CVE-2026-9301", "WatchGuard", "Firebox T35", "12.4.0 - 12.4.2", 9.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", False),
    ("CVE-2026-9302", "WatchGuard", "Firebox T35", "12.0.0 - 12.4.0", 7.7,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", True),
    ("CVE-2026-9303", "WatchGuard", "Firebox T35", "12.4.0", 8.4,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", True),
    ("CVE-2026-9304", "WatchGuard", "Firebox T35", "12.2.0 - 12.4.0", 5.9,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", True),
    # ---- Um equipamento fora do inventario: prova que o filtro funciona ----
    ("CVE-2026-9401", "Fortinet", "FortiGate 200F", "7.0.0 - 7.4.1", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
    ("CVE-2026-9402", "Cisco", "Catalyst 9300", "15.0.0 - 15.2.4", 8.6,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", True),
    ("CVE-2026-9403", "Juniper", "EX9200", "12.3.0 - 12.3.1", 9.0,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),
]

#: Descricoes geradas a partir do id, para o arquivo ter texto real por CVE.
#: Nao ha texto de CVE real aqui: sao frases de laboratorio que descrevem o
#: vetor, escritas a partir do proprio vetor CVSS.
_TIPOS = {
    9.8: "Falha critica de execucao remota sem autenticacao.",
    9.5: "Falha critica de execucao remota com privilegios baixos.",
    9.3: "Falha de escalonamento de privilegio com alteracao de escopo.",
    9.1: "Falha grave de execucao remota, exige configuracao especifica.",
    9.0: "Falha grave de corrupcao de memoria alcanavel pela rede.",
    8.8: "Falha de divulgacao de informacao com impacto alto.",
    8.6: "Falha de integridade com privilegios baixos.",
    8.4: "Falha de autenticacao contornavel.",
    8.2: "Falha de divulgacao de informacao em canal seguro.",
    8.1: "Falha de divulgacao de informacao, exige mais condicoes.",
    7.8: "Negacao de servico em rede adjacente.",
    7.7: "Falha de confidencialidade com privilegios necessarios.",
    7.5: "Falha de disponibilidade ou integridade com privilegios.",
    7.4: "Negacao de servico ou divulgacao em rede local.",
    7.2: "Falha de integridade com privilegios de usuario.",
    6.5: "Falha de autenticacao fraca em servico de rede.",
    6.2: "Falha de divulgacao com rede adjacente.",
    6.1: "Falha de autorizacao insuficiente.",
    5.9: "Negacao de servico local com consequencia limitada.",
    5.8: "Falha de integridade com rede de alta complexidade.",
    5.4: "Falha de divulgacao em rede adjacente com privilegios.",
    5.3: "Falha que exige interacao do usuario.",
    5.0: "Falha local com consequencia moderada.",
    4.9: "Falha local com integridade parcial.",
    4.7: "Falha de divulgacao em rede local.",
    4.4: "Falha de integridade em rede adjacente.",
    4.3: "Falha de divulgacao local com privilegios.",
    4.0: "Falha de integridade com rede adjacente.",
    3.9: "Falha local com negacao de servico limitada.",
    3.7: "Falha de integridade local com privilegios.",
    3.5: "Falha de integridade local em rede adjacente.",
    3.3: "Falha de integridade local.",
    3.1: "Falha local de consequencia baixa.",
}


def descricao_para(cve_id: str, cvss: float, vector: str) -> str:
    """Monta a descricao de uma CVE sintetica.

    Build the description of a synthetic CVE.

    Args:
        cve_id: Identificador da CVE.
        cvss: Pontuacao CVSS.
        vector: Vetor de ataque.

    Returns:
        Frase de laboratorio derivada do vetor.
    """
    tipo = _TIPOS.get(cvss, "Falha de seguranca registrada em laboratorio.")
    partes = vector.split("/")[1:]
    dimensoes = " ".join(partes[:3]) if partes else ""
    return f"[{cve_id}] {tipo} Vetor: {dimensoes}."


def main() -> int:
    """Escreve o arquivo de CVEs.

    Write the CVE file.
    """
    registros = []
    for cve_id, fabricante, modelo, faixa, cvss, vector, workaround in LINHAS:
        registros.append({
            "id": cve_id,
            "description": descricao_para(cve_id, cvss, vector),
            "cvss": cvss,
            "vector": vector,
            "affected_version": faixa,
            "manufacturer": fabricante,
            "model": modelo,
            "workaround": workaround,
        })

    DESTINO.parent.mkdir(exist_ok=True)
    DESTINO.write_text(
        json.dumps(registros, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"{len(registros)} CVEs escritas em {DESTINO.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())