import datetime

# base de dados local com técnicas reais do mitre att&ck.
# cada técnica inclui sua tática, fase da kill chain e recomendação defensiva.
TECNICAS = {
    "T1566.001": {
        "nome": "Spearphishing Attachment",
        "tatica": "Initial Access",
        "kill_chain_fase": 3,
        "descricao": "Atacante envia e-mail com arquivo malicioso anexado.",
        "recomendacao": "Configurar filtro de anexos no e-mail corporativo e atualizar leitores de PDF/Office."
    },
    "T1566.002": {
        "nome": "Spearphishing Link",
        "tatica": "Initial Access",
        "kill_chain_fase": 3,
        "descricao": "Atacante envia e-mail com link malicioso.",
        "recomendacao": "Ativar verificação de URLs em tempo real e treinar funcionários para identificar links suspeitos."
    },
    "T1203": {
        "nome": "Exploitation for Client Execution",
        "tatica": "Execution",
        "kill_chain_fase": 4,
        "descricao": "Atacante explora vulnerabilidade em software do cliente (ex: PDF, navegador).",
        "recomendacao": "Manter softwares atualizados e aplicar patches de segurança imediatamente."
    },
    "T1071.001": {
        "nome": "Web Protocols (C2)",
        "tatica": "Command and Control",
        "kill_chain_fase": 6,
        "descricao": "Atacante usa HTTP/HTTPS para se comunicar com sistemas comprometidos.",
        "recomendacao": "Monitorar tráfego para domínios recém-registrados e usar proxy com inspeção TLS."
    },
    "T1059.001": {
        "nome": "PowerShell",
        "tatica": "Execution",
        "kill_chain_fase": 5,
        "descricao": "Atacante usa PowerShell para executar comandos maliciosos.",
        "recomendacao": "Restringir execução de scripts PowerShell e monitorar logs do sistema."
    },
    "T1078": {
        "nome": "Valid Accounts",
        "tatica": "Defense Evasion / Persistence",
        "kill_chain_fase": 4,
        "descricao": "Atacante usa credenciais legítimas para se mover sem ser detectado.",
        "recomendacao": "Implementar MFA e monitorar logins em horários ou locais incomuns."
    },
    "T1486": {
        "nome": "Data Encrypted for Impact (Ransomware)",
        "tatica": "Impact",
        "kill_chain_fase": 7,
        "descricao": "Atacante criptografa dados da vítima para extorquir resgate.",
        "recomendacao": "Manter backups offline testados e segmentar a rede para limitar propagação."
    },
    "T1595": {
        "nome": "Active Scanning",
        "tatica": "Reconnaissance",
        "kill_chain_fase": 1,
        "descricao": "Atacante faz varredura ativa para descobrir portas e vulnerabilidades.",
        "recomendacao": "Implementar honeypots e alertas para varreduras de porta incomuns."
    },
}

# as 7 fases da cyber kill chain (modelo lockheed martin).
# representam o ciclo completo de um ataque, do reconhecimento à ação final.
KILL_CHAIN = {
    1: "Reconhecimento",
    2: "Armamento",
    3: "Entrega",
    4: "Exploração",
    5: "Instalação",
    6: "Comando e Controle",
    7: "Ação Final"
}


def gerar_header():
    print("-" * 60)
    print("🕵️ CTI MAPPER — MAPEADOR DE CIBERINTELIGÊNCIA")
    print(f"Data da análise: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print("-" * 60)


def listar_tecnicas():
    """
    exibe todas as técnicas disponíveis na base de dados local.
    útil para o analista explorar o que pode ser consultado.
    """
    print("\n📋 TÉCNICAS DISPONÍVEIS (MITRE ATT&CK)...")
    print("-" * 60)
    for codigo, dados in TECNICAS.items():
        print(f"  [+] {codigo:12} → {dados['nome']}  [{dados['tatica']}]")
    print("-" * 60)


def consultar_tecnica(codigo):
    """
    busca uma técnica pelo código e exibe detalhes completos.
    inclui o posicionamento na cyber kill chain para contexto defensivo.
    """
    codigo = codigo.upper().strip()

    if codigo not in TECNICAS:
        print(f"\n❌ técnica '{codigo}' não encontrada na base de dados.")
        print("   use a opção 3 para ver os códigos disponíveis.")
        return

    t = TECNICAS[codigo]
    fase = t["kill_chain_fase"]

    print(f"\n🎯 MITRE ATT&CK — {codigo}")
    print("-" * 60)
    print(f"  Nome     : {t['nome']}")
    print(f"  Tática   : {t['tatica']}")
    print(f"  Descrição: {t['descricao']}")
    print(f"\n  ✅ Recomendação defensiva:")
    print(f"     {t['recomendacao']}")

    print(f"\n📌 CYBER KILL CHAIN — fase atual do ataque:")
    print("-" * 60)
    for numero, nome in KILL_CHAIN.items():
        if numero == fase:
            print(f"  ▶ Fase {numero}: {nome}  ← AQUI")
        else:
            print(f"    Fase {numero}: {nome}")
    print("-" * 60)


def classificar_indicador(indicador):
    """
    classifica um indicador na pirâmide da dor.
    quanto mais alto na pirâmide, mais custa ao atacante mudar aquele indicador.
    """
    indicador = indicador.strip().lower()

    # hash md5 (32 chars) ou sha256 (64 chars) — base da pirâmide
    if len(indicador) in [32, 64] and all(c in "0123456789abcdef" for c in indicador):
        nivel = "🔴 Nível 1 — Base da pirâmide (TRIVIAL para o atacante mudar)"
        explicacao = "O atacante recompila o malware e o hash muda em segundos. Útil no curto prazo, mas insuficiente."

    # endereço ip — quatro blocos numéricos separados por ponto
    elif len(indicador.split(".")) == 4 and all(p.isdigit() for p in indicador.split(".")):
        nivel = "🟠 Nível 2 — Fácil de mudar"
        explicacao = "O atacante troca para outro servidor em minutos. Necessário bloquear, mas não é suficiente sozinho."

    # domínio — tem ponto, mas não é ip
    elif "." in indicador and not indicador.replace(".", "").isdigit():
        nivel = "🟡 Nível 3 — Moderado"
        explicacao = "Registrar um novo domínio tem custo, mas ainda é relativamente simples. Combine com análise de TTPs."

    # ferramentas conhecidas usadas por atacantes
    elif any(f in indicador for f in ["mimikatz", "cobalt strike", "metasploit", "empire", "nmap", "bloodhound"]):
        nivel = "🟢 Nível 4 — Difícil de mudar"
        explicacao = "Trocar de ferramenta exige tempo e adaptação. Detectar o uso de ferramentas específicas é muito valioso."

    # ttp — começa com 't' e tem pelo menos 5 caracteres (ex: t1566)
    elif indicador.startswith("t") and len(indicador) >= 5:
        nivel = "🔵 Nível 5 — Topo da pirâmide (MUITO difícil de mudar)"
        explicacao = "Mudar um TTP significa mudar como o atacante opera inteiramente. É o indicador mais estratégico."

    else:
        nivel = "⚪ Não classificado"
        explicacao = "Tente: IP, hash MD5/SHA256, domínio, nome de ferramenta ou código de técnica (ex: T1566.001)."

    print(f"\n🔍 PIRÂMIDE DA DOR — Análise do Indicador")
    print("-" * 60)
    print(f"  Indicador : {indicador}")
    print(f"  Posição   : {nivel}")
    print(f"\n  💡 Explicação:")
    print(f"     {explicacao}")
    print("-" * 60)


def menu():
    """
    loop principal da ferramenta.
    permite ao analista consultar técnicas e classificar indicadores de forma interativa.
    """
    gerar_header()

    while True:
        print("\n  1. Consultar técnica MITRE ATT&CK")
        print("  2. Classificar indicador (Pirâmide da Dor)")
        print("  3. Ver todas as técnicas disponíveis")
        print("  0. Sair")

        opcao = input("\n  Opção: ").strip()

        if opcao == "1":
            codigo = input("  Digite o código da técnica (ex: T1566.001): ")
            consultar_tecnica(codigo)

        elif opcao == "2":
            indicador = input("  Digite o indicador (IP, hash, domínio, ferramenta ou código TTP): ")
            classificar_indicador(indicador)

        elif opcao == "3":
            listar_tecnicas()

        elif opcao == "0":
            print("\n  Até mais! 👋\n")
            break

        else:
            print("  ⚠️  Opção inválida. Tente novamente.")


if __name__ == "__main__":
    menu()