#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inventário de chaves criptográficas dos Azure Key Vaults de um tenant Azure.

Percorre todas as subscriptions do tenant, lista os Key Vaults, suas chaves e
segredos usando apenas as APIs de gerenciamento (Azure Resource Manager), e
gera um relatório final apenas com as chaves "stand-alone" que possuem data de
expiração. Foi pensado para rodar no Python nativo do Azure Cloud Shell, sem
dependências externas além do Azure CLI (usado apenas para obter o token).
"""

import csv
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# -------------------------------------------------------------------
# Versões de API do Azure Resource Manager
# -------------------------------------------------------------------
API_SUBSCRIPTIONS = "2022-12-01"
API_KEY_VAULT = "2023-07-01"
BASE_ARM = "https://management.azure.com"

# -------------------------------------------------------------------
# Arquivos de saída (também servem de cache local)
# -------------------------------------------------------------------
ARQUIVO_SUBSCRIPTIONS = "subscriptions.csv"
ARQUIVO_KEY_VAULTS = "keyvaults.csv"
ARQUIVO_CHAVES = "keys.csv"
ARQUIVO_SECRETS = "secrets.csv"
ARQUIVO_CHAVES_FILTRADAS = "chaves_filtradas.csv"

# contentType que identifica um segredo gerado por um certificado
CONTENT_TYPE_CERTIFICADO = "application/x-pkcs12"

# Cabeçalhos dos CSVs
CAB_SUBSCRIPTIONS = ["subscription_id", "nome"]
CAB_KEY_VAULTS = ["subscription_id", "resource_group", "nome_cofre"]
CAB_CHAVES = [
    "subscription_id",
    "resource_group",
    "nome_cofre",
    "nome_chave",
    "data_expiracao",
    "tem_expiracao",
]
CAB_SECRETS = [
    "subscription_id",
    "resource_group",
    "nome_cofre",
    "nome_secret",
    "content_type",
]
CAB_CHAVES_FILTRADAS = [
    "subscription_id",
    "resource_group",
    "nome_cofre",
    "nome_chave",
    "data_expiracao",
]

# Cache do token de acesso ao ARM (valor, epoch de expiração)
_token_cache = {"valor": None, "expira_em": 0}


# ===================================================================
# Autenticação / chamadas ao ARM
# ===================================================================
def obter_token():
    """Obtém (e reaproveita) um token de acesso ao ARM via Azure CLI."""

    agora = time.time()
    if _token_cache["valor"] and agora < _token_cache["expira_em"] - 60:
        return _token_cache["valor"]

    try:
        resultado = subprocess.run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                BASE_ARM,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print(
            "ERRO: comando 'az' não encontrado. Execute este script no Azure "
            "Cloud Shell ou instale o Azure CLI.",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as erro:
        print(
            "ERRO ao obter token de acesso. Verifique se você está logado "
            "('az login'):\n" + (erro.stderr or ""),
            file=sys.stderr,
        )
        sys.exit(1)

    dados = json.loads(resultado.stdout)
    _token_cache["valor"] = dados["accessToken"]
    # Renova a cada 30 min por segurança, independente do expiresOn informado.
    _token_cache["expira_em"] = agora + 30 * 60
    return _token_cache["valor"]


def chamar_arm_paginado(url):
    """Faz GET no ARM tratando a paginação (nextLink).

    Retorna a lista completa de itens de 'value'. Em caso de erro no recurso
    (ex.: acesso negado a um cofre), informa e devolve o que conseguiu obter.
    """

    itens = []

    while url:
        token = obter_token()
        requisicao = urllib.request.Request(url)
        requisicao.add_header("Authorization", "Bearer " + token)
        requisicao.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(requisicao, timeout=120) as resposta:
                corpo = json.loads(resposta.read().decode("utf-8"))
        except urllib.error.HTTPError as erro:
            detalhe = ""
            try:
                detalhe = erro.read().decode("utf-8")
            except Exception:
                pass
            print(
                "    AVISO: falha HTTP {} ao acessar recurso. {}".format(
                    erro.code, detalhe[:300]
                ),
                flush=True,
            )
            break
        except urllib.error.URLError as erro:
            print(
                "    AVISO: falha de rede ao acessar recurso: {}".format(
                    erro.reason),
                flush=True,
            )
            break

        itens.extend(corpo.get("value", []))
        url = corpo.get("nextLink") or None

    return itens


# ===================================================================
# Utilitários de CSV
# ===================================================================
def escrever_csv(caminho, cabecalho, linhas):
    """Grava um CSV completo (sobrescrevendo) com cabeçalho e linhas."""

    with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(cabecalho)
        escritor.writerows(linhas)


def ler_csv(caminho):
    """Lê um CSV como lista de dicionários. Retorna [] se não existir."""

    if not os.path.exists(caminho):
        return []

    with open(caminho, "r", newline="", encoding="utf-8") as arquivo:
        return list(csv.DictReader(arquivo))


# ===================================================================
# Etapas do inventário
# ===================================================================
def listar_subscriptions():
    """Lista todas as subscriptions do tenant e grava em subscriptions.csv."""

    print("Listando subscriptions...", flush=True)

    url = "{}/subscriptions?api-version={}".format(BASE_ARM, API_SUBSCRIPTIONS)
    subscriptions = chamar_arm_paginado(url)

    linhas = []
    for sub in subscriptions:
        linhas.append([sub.get("subscriptionId", ""),
                      sub.get("displayName", "")])

    escrever_csv(ARQUIVO_SUBSCRIPTIONS, CAB_SUBSCRIPTIONS, linhas)
    print(
        "  -> {} subscription(s) salva(s) em {}".format(
            len(linhas), ARQUIVO_SUBSCRIPTIONS
        ),
        flush=True,
    )
    return ler_csv(ARQUIVO_SUBSCRIPTIONS)


def listar_key_vaults(subscriptions):
    """Lista os Key Vaults de cada subscription e grava em keyvaults.csv."""

    print("\nListando Key Vaults...", flush=True)

    total = len(subscriptions)
    linhas = []

    for indice, sub in enumerate(subscriptions, start=1):
        subscription_id = sub["subscription_id"]
        nome_sub = sub["nome"]
        print(
            "  Processando subscription {} de {}: {}".format(
                indice, total, nome_sub),
            flush=True,
        )

        url = (
            "{}/subscriptions/{}/providers/Microsoft.KeyVault/vaults"
            "?api-version={}".format(BASE_ARM, subscription_id, API_KEY_VAULT)
        )
        cofres = chamar_arm_paginado(url)

        for cofre in cofres:
            partes = cofre.get("id", "").split("/")
            resource_group = partes[4] if len(partes) > 4 else ""
            linhas.append(
                [subscription_id, resource_group, cofre.get("name", "")])

        print("    Key Vaults encontrados: {}".format(len(cofres)), flush=True)

    escrever_csv(ARQUIVO_KEY_VAULTS, CAB_KEY_VAULTS, linhas)
    print(
        "  -> {} Key Vault(s) salvo(s) em {}".format(len(linhas),
                                                     ARQUIVO_KEY_VAULTS),
        flush=True,
    )
    return ler_csv(ARQUIVO_KEY_VAULTS)


def _epoch_para_iso(epoch):
    """Converte um timestamp epoch (segundos) em texto ISO 8601 UTC."""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))


def listar_chaves(cofres):
    """Lista todas as chaves de cada Key Vault e grava em keys.csv."""

    print("\nListando chaves criptográficas...", flush=True)

    total = len(cofres)
    linhas = []

    for indice, cofre in enumerate(cofres, start=1):
        subscription_id = cofre["subscription_id"]
        resource_group = cofre["resource_group"]
        nome_cofre = cofre["nome_cofre"]
        print(
            "  Processando Key Vault {} de {}: {}".format(
                indice, total, nome_cofre),
            flush=True,
        )

        url = (
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault"
            "/vaults/{}/keys?api-version={}".format(
                BASE_ARM, subscription_id, resource_group, nome_cofre, API_KEY_VAULT
            )
        )
        chaves = chamar_arm_paginado(url)

        for chave in chaves:
            atributos = chave.get("properties", {}).get("attributes", {})
            exp = atributos.get("exp")
            tem_expiracao = exp is not None
            data_expiracao = _epoch_para_iso(exp) if tem_expiracao else ""
            linhas.append(
                [
                    subscription_id,
                    resource_group,
                    nome_cofre,
                    chave.get("name", ""),
                    data_expiracao,
                    "sim" if tem_expiracao else "nao",
                ]
            )

        print("    Chaves encontradas: {}".format(len(chaves)), flush=True)

    escrever_csv(ARQUIVO_CHAVES, CAB_CHAVES, linhas)
    print(
        "  -> {} chave(s) salva(s) em {}".format(len(linhas), ARQUIVO_CHAVES),
        flush=True,
    )
    return ler_csv(ARQUIVO_CHAVES)


def listar_secrets(cofres):
    """Lista todos os segredos de cada Key Vault e grava em secrets.csv."""

    print("\nListando segredos...", flush=True)

    total = len(cofres)
    linhas = []

    for indice, cofre in enumerate(cofres, start=1):
        subscription_id = cofre["subscription_id"]
        resource_group = cofre["resource_group"]
        nome_cofre = cofre["nome_cofre"]
        print(
            "  Processando Key Vault {} de {}: {}".format(
                indice, total, nome_cofre),
            flush=True,
        )

        url = (
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault"
            "/vaults/{}/secrets?api-version={}".format(
                BASE_ARM, subscription_id, resource_group, nome_cofre, API_KEY_VAULT
            )
        )
        segredos = chamar_arm_paginado(url)

        for segredo in segredos:
            content_type = segredo.get("properties", {}).get(
                "contentType", "") or ""
            linhas.append(
                [
                    subscription_id,
                    resource_group,
                    nome_cofre,
                    segredo.get("name", ""),
                    content_type,
                ]
            )

        print("    Segredos encontrados: {}".format(len(segredos)), flush=True)

    escrever_csv(ARQUIVO_SECRETS, CAB_SECRETS, linhas)
    print(
        "  -> {} segredo(s) salvo(s) em {}".format(len(linhas),
                                                   ARQUIVO_SECRETS),
        flush=True,
    )
    return ler_csv(ARQUIVO_SECRETS)


def filtrar_chaves(chaves, secrets):
    """Gera chaves_filtradas.csv apenas com chaves stand-alone expiráveis.

    Regras:
      - a chave precisa ter data de expiração;
      - a chave não pode ser de certificado, ou seja, não pode existir um
        segredo com contentType 'application/x-pkcs12' e mesmo nome no cofre.
    """

    print("\nFiltrando chaves stand-alone com expiração...", flush=True)

    # Conjunto de (cofre, nome) que correspondem a segredos de certificado.
    nomes_certificado = set()
    for secret in secrets:
        if secret.get("content_type", "") == CONTENT_TYPE_CERTIFICADO:
            nomes_certificado.add(
                (secret["nome_cofre"], secret["nome_secret"]))

    linhas = []
    for chave in chaves:
        if chave.get("tem_expiracao", "") != "sim":
            continue
        chave_ref = (chave["nome_cofre"], chave["nome_chave"])
        if chave_ref in nomes_certificado:
            continue
        linhas.append(
            [
                chave["subscription_id"],
                chave["resource_group"],
                chave["nome_cofre"],
                chave["nome_chave"],
                chave["data_expiracao"],
            ]
        )

    escrever_csv(ARQUIVO_CHAVES_FILTRADAS, CAB_CHAVES_FILTRADAS, linhas)
    print(
        "  -> {} chave(s) stand-alone salva(s) em {}".format(
            len(linhas), ARQUIVO_CHAVES_FILTRADAS
        ),
        flush=True,
    )


# ===================================================================
# Cache local
# ===================================================================
def preparar_cache():
    """Verifica CSVs existentes e pergunta se recomeça do zero ou continua.

    Retorna True se deve reaproveitar o cache existente (modo continuar),
    ou False se o usuário optou por recomeçar (arquivos apagados).
    """

    arquivos = [
        ARQUIVO_SUBSCRIPTIONS,
        ARQUIVO_KEY_VAULTS,
        ARQUIVO_CHAVES,
        ARQUIVO_SECRETS,
        ARQUIVO_CHAVES_FILTRADAS,
    ]
    existentes = [a for a in arquivos if os.path.exists(a)]

    if not existentes:
        return False

    print("Foram encontrados arquivos CSV de execuções anteriores:", flush=True)
    for arquivo in existentes:
        print("  - {}".format(arquivo), flush=True)

    while True:
        resposta = input(
            "Deseja (C)ontinuar de onde parou ou (R)ecomeçar do zero? [C/R]: "
        ).strip().lower()
        if resposta in ("c", "continuar", ""):
            print("Continuando a partir do cache existente.\n", flush=True)
            return True
        if resposta in ("r", "recomecar", "recomeçar"):
            for arquivo in existentes:
                os.remove(arquivo)
            print("Cache apagado. Recomeçando do zero.\n", flush=True)
            return False
        print("Resposta inválida. Digite C para continuar ou R para recomeçar.")


def etapa_concluida(caminho, continuar):
    """Indica se uma etapa já foi concluída e pode ser reaproveitada do cache."""

    return continuar and os.path.exists(caminho)


# ===================================================================
# MAIN
# ===================================================================
def principal():
    print("==================================================", flush=True)
    print(" Inventário de chaves stand-alone dos Azure Key Vaults", flush=True)
    print("==================================================\n", flush=True)

    continuar = preparar_cache()

    # Etapa 1 - Subscriptions
    if etapa_concluida(ARQUIVO_SUBSCRIPTIONS, continuar):
        print("Subscriptions já inventariadas (cache).", flush=True)
        subscriptions = ler_csv(ARQUIVO_SUBSCRIPTIONS)
    else:
        subscriptions = listar_subscriptions()

    # Etapa 2 - Key Vaults
    if etapa_concluida(ARQUIVO_KEY_VAULTS, continuar):
        print("Key Vaults já inventariados (cache).", flush=True)
        cofres = ler_csv(ARQUIVO_KEY_VAULTS)
    else:
        cofres = listar_key_vaults(subscriptions)

    # Etapa 3 - Chaves
    if etapa_concluida(ARQUIVO_CHAVES, continuar):
        print("Chaves já inventariadas (cache).", flush=True)
        chaves = ler_csv(ARQUIVO_CHAVES)
    else:
        chaves = listar_chaves(cofres)

    # Etapa 4 - Segredos
    if etapa_concluida(ARQUIVO_SECRETS, continuar):
        print("Segredos já inventariados (cache).", flush=True)
        secrets = ler_csv(ARQUIVO_SECRETS)
    else:
        secrets = listar_secrets(cofres)

    # Etapa 5 - Filtro final (sempre recalculado a partir dos CSVs locais)
    filtrar_chaves(chaves, secrets)

    print("\nConcluído.", flush=True)


if __name__ == "__main__":
    try:
        principal()
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo usuário.", flush=True)
        sys.exit(130)
