#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gerador de massa de teste para o inventario_akv.py.

Cria Key Vaults e chaves criptográficas com datas de expiração variadas (e
algumas sem data) para exercitar o inventário em escala.

Assim como o inventário, usa apenas o plano de gerenciamento
(management.azure.com) e a biblioteca padrão do Python. Isso é o que permite
criar as chaves mesmo sem acesso de rede ao data plane dos cofres.

    # criar 20 cofres com 1000 chaves cada
    python3 gerar_massa_teste.py --grupo rg-carga-akv

    # apagar tudo o que foi criado (exclusão + purge)
    python3 gerar_massa_teste.py --grupo rg-carga-akv --remover

A execução é idempotente: rodar de novo cria apenas o que faltou.
"""

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import random
import subprocess
import sys
import threading
import time
import urllib.parse

HOST_ARM = "management.azure.com"
BASE_ARM = "https://" + HOST_ARM
API_KEY_VAULT = "2023-07-01"
API_GRUPOS = "2021-04-01"
TENTATIVAS_MAXIMAS = 6
TIMEOUT_HTTP = 60

# Faixa de vencimentos sorteados: um pouco no passado (chaves já vencidas) até
# cerca de três anos à frente.
DIAS_MINIMO = -120
DIAS_MAXIMO = 1095


class ErroArm(Exception):
    pass


# ===================================================================
# Cliente ARM
# ===================================================================
class ClienteArm:
    def __init__(self):
        self._local = threading.local()
        self._token = None
        self._expira_em = 0.0
        self._trava = threading.Lock()
        self.requisicoes = 0

    def token(self):
        with self._trava:
            if self._token and time.time() < self._expira_em:
                return self._token
            try:
                saida = subprocess.run(
                    ["az", "account", "get-access-token", "--resource", BASE_ARM,
                     "--output", "json"],
                    capture_output=True, text=True, check=True,
                )
            except FileNotFoundError:
                raise ErroArm("comando 'az' não encontrado.")
            except subprocess.CalledProcessError as erro:
                raise ErroArm(
                    "não foi possível obter o token: " + (erro.stderr or ""))
            self._token = json.loads(saida.stdout)["accessToken"]
            self._expira_em = time.time() + 25 * 60
            return self._token

    def _conexao(self):
        conexao = getattr(self._local, "conexao", None)
        if conexao is None:
            conexao = http.client.HTTPSConnection(
                HOST_ARM, timeout=TIMEOUT_HTTP)
            self._local.conexao = conexao
        return conexao

    def _descartar(self):
        conexao = getattr(self._local, "conexao", None)
        if conexao is not None:
            try:
                conexao.close()
            except Exception:
                pass
            self._local.conexao = None

    def requisitar(self, metodo, caminho, corpo=None, aceitar=(200, 201, 202)):
        dados = json.dumps(corpo).encode(
            "utf-8") if corpo is not None else None
        ultimo = "causa desconhecida"

        for tentativa in range(1, TENTATIVAS_MAXIMAS + 1):
            cabecalhos = {"Authorization": "Bearer " + self.token(),
                          "Accept": "application/json"}
            if dados is not None:
                cabecalhos["Content-Type"] = "application/json"
            try:
                conexao = self._conexao()
                conexao.request(metodo, caminho, body=dados,
                                headers=cabecalhos)
                resposta = conexao.getresponse()
                bruto = resposta.read()
                status = resposta.status
                cabecalhos_resposta = {
                    c.lower(): v for c, v in resposta.getheaders()}
            except Exception as erro:
                self._descartar()
                ultimo = "falha de rede: {}".format(erro)
                time.sleep(min(30.0, 2.0 ** tentativa) + random.random())
                continue

            self.requisicoes += 1

            if status in aceitar:
                return json.loads(bruto.decode("utf-8")) if bruto else {}
            if status == 404 and 404 in aceitar:
                return {}

            detalhe = bruto.decode("utf-8", "replace").strip()[:300]
            if status == 429 or status >= 500:
                espera = cabecalhos_resposta.get("retry-after")
                try:
                    espera = float(espera)
                except (TypeError, ValueError):
                    espera = min(30.0, 2.0 ** tentativa) + random.random()
                ultimo = "HTTP {} -- {}".format(status, detalhe)
                time.sleep(espera)
                continue
            raise ErroArm(
                "HTTP {} em {} -- {}".format(status, caminho, detalhe))

        raise ErroArm(
            "falhou após {} tentativas -- {}".format(TENTATIVAS_MAXIMAS, ultimo))


# ===================================================================
# Contexto da assinatura
# ===================================================================
def contexto_azure():
    try:
        saida = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise ErroArm("não consegui ler a conta atual. Rode 'az login'.")
    dados = json.loads(saida.stdout)
    return dados["id"], dados["tenantId"], dados.get("name", "")


def sufixo_estavel(subscription_id, grupo):
    """Sufixo determinístico: reexecuções apontam para os mesmos cofres."""

    digest = hashlib.sha256((subscription_id + "|" + grupo).encode("utf-8"))
    return digest.hexdigest()[:4]


# ===================================================================
# Criação
# ===================================================================
def garantir_grupo(cliente, subscription_id, grupo, local):
    caminho = "/subscriptions/{}/resourcegroups/{}?api-version={}".format(
        subscription_id, urllib.parse.quote(grupo), API_GRUPOS
    )
    cliente.requisitar("PUT", caminho, {"location": local})


def caminho_cofre(subscription_id, grupo, nome):
    return (
        "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault"
        "/vaults/{}".format(subscription_id, urllib.parse.quote(grupo),
                            urllib.parse.quote(nome))
    )


def criar_cofre(cliente, subscription_id, tenant_id, grupo, local, nome):
    caminho = caminho_cofre(subscription_id, grupo, nome)
    corpo = {
        "location": local,
        "properties": {
            "tenantId": tenant_id,
            "sku": {"family": "A", "name": "standard"},
            "enableRbacAuthorization": True,
            "enableSoftDelete": True,
            "softDeleteRetentionInDays": 7,
        },
    }
    try:
        cliente.requisitar(
            "PUT", caminho + "?api-version=" + API_KEY_VAULT, corpo)
    except ErroArm as erro:
        if "already exists in deleted state" in str(erro) or "VaultAlreadyExists" in str(erro):
            raise ErroArm(
                "o cofre '{}' existe em estado 'soft-deleted'. Rode com "
                "--remover para fazer o purge antes de recriar.".format(nome)
            )
        raise

    # O cofre passa por 'RegisteringDns' e recusa chaves até ficar 'Succeeded'.
    for _ in range(60):
        estado = cliente.requisitar(
            "GET", caminho + "?api-version=" + API_KEY_VAULT
        ).get("properties", {}).get("provisioningState")
        if estado == "Succeeded":
            return
        time.sleep(2)
    raise ErroArm("o cofre '{}' não ficou pronto a tempo".format(nome))


def chaves_existentes(cliente, subscription_id, grupo, nome_cofre):
    caminho = caminho_cofre(subscription_id, grupo, nome_cofre) + \
        "/keys?api-version=" + API_KEY_VAULT
    nomes = set()
    while caminho:
        corpo = cliente.requisitar("GET", caminho, aceitar=(200, 404))
        for item in corpo.get("value") or []:
            nomes.add(item.get("name"))
        proxima = corpo.get("nextLink")
        if not proxima:
            break
        partes = urllib.parse.urlsplit(proxima)
        caminho = partes.path + (("?" + partes.query) if partes.query else "")
    return nomes


def criar_chave(cliente, subscription_id, grupo, nome_cofre, nome_chave,
                expiracao, usar_rsa):
    if usar_rsa:
        propriedades = {"kty": "RSA", "keySize": 2048}
    else:
        propriedades = {"kty": "EC", "curveName": "P-256"}
    atributos = {"enabled": True}
    if expiracao is not None:
        atributos["exp"] = expiracao
    propriedades["attributes"] = atributos

    caminho = "{}/keys/{}?api-version={}".format(
        caminho_cofre(subscription_id, grupo, nome_cofre),
        urllib.parse.quote(nome_chave), API_KEY_VAULT,
    )
    cliente.requisitar("PUT", caminho, {"properties": propriedades})


def sortear_expiracao(agora, proporcao_sem_data):
    if random.random() < proporcao_sem_data:
        return None
    return int(agora + random.randint(DIAS_MINIMO, DIAS_MAXIMO) * 86400)


# ===================================================================
# Remoção
# ===================================================================
def listar_cofres_do_prefixo(cliente, subscription_id, prefixo):
    caminho = "/subscriptions/{}/providers/Microsoft.KeyVault/vaults" \
        "?api-version={}".format(subscription_id, API_KEY_VAULT)
    encontrados = []
    while caminho:
        corpo = cliente.requisitar("GET", caminho)
        for item in corpo.get("value") or []:
            if (item.get("name") or "").startswith(prefixo):
                encontrados.append(
                    {"nome": item.get("name"),
                     "local": item.get("location"),
                     "id": item.get("id")}
                )
        proxima = corpo.get("nextLink")
        if not proxima:
            break
        partes = urllib.parse.urlsplit(proxima)
        caminho = partes.path + (("?" + partes.query) if partes.query else "")
    return encontrados


def remover_cofre(cliente, subscription_id, grupo, cofre):
    cliente.requisitar(
        "DELETE",
        caminho_cofre(subscription_id, grupo, cofre["nome"]) +
        "?api-version=" + API_KEY_VAULT,
        aceitar=(200, 202, 204, 404),
    )
    cliente.requisitar(
        "POST",
        "/subscriptions/{}/providers/Microsoft.KeyVault/locations/{}"
        "/deletedVaults/{}/purge?api-version={}".format(
            subscription_id, cofre["local"],
            urllib.parse.quote(cofre["nome"]), API_KEY_VAULT),
        aceitar=(200, 202, 204, 404),
    )


# ===================================================================
# Progresso
# ===================================================================
class Progresso:
    def __init__(self, rotulo, total):
        self.rotulo = rotulo
        self.total = max(1, total)
        self.feitos = 0
        self.falhas = 0
        self._inicio = time.monotonic()
        self._trava = threading.Lock()
        self._ultimo = 0.0
        self._tty = sys.stdout.isatty()

    def avancar(self, falhou=False):
        with self._trava:
            self.feitos += 1
            if falhou:
                self.falhas += 1
            agora = time.monotonic()
            if agora - self._ultimo < (0.5 if self._tty else 10.0) and \
                    self.feitos < self.total:
                return
            self._ultimo = agora
            self._desenhar()

    def _desenhar(self):
        decorrido = time.monotonic() - self._inicio
        fracao = self.feitos / float(self.total)
        taxa = self.feitos / decorrido if decorrido > 0 else 0.0
        restante = (self.total - self.feitos) / taxa if taxa > 0 else 0
        linha = "  [{:3.0f}%] {} {}/{} | {:.1f}/s | {} falha(s) | restam ~{}".format(
            fracao * 100, self.rotulo, self.feitos, self.total, taxa,
            self.falhas, _duracao(restante),
        )
        if self._tty:
            sys.stdout.write("\r" + linha.ljust(96)[:96])
        else:
            sys.stdout.write(linha + "\n")
        sys.stdout.flush()

    def encerrar(self):
        with self._trava:
            self._desenhar()
        if self._tty:
            sys.stdout.write("\n")
        sys.stdout.flush()


def _duracao(segundos):
    segundos = int(max(0, segundos))
    if segundos >= 3600:
        return "{}h{:02d}m".format(segundos // 3600, (segundos % 3600) // 60)
    return "{:02d}:{:02d}".format(segundos // 60, segundos % 60)


# ===================================================================
# MAIN
# ===================================================================
def analisar_argumentos(argv):
    a = argparse.ArgumentParser(
        description="Cria massa de teste (Key Vaults e chaves) para exercitar "
                    "o inventario_akv.py.",
    )
    a.add_argument("--grupo", required=True, metavar="RG",
                   help="resource group onde criar os cofres (criado se não existir)")
    a.add_argument("--local", default="eastus", help="região (padrão: eastus)")
    a.add_argument("--cofres", type=int, default=20,
                   help="quantos cofres (padrão: 20)")
    a.add_argument("--chaves", type=int, default=1000,
                   help="chaves por cofre (padrão: 1000)")
    a.add_argument("--prefixo", default="akv-carga",
                   help="prefixo dos nomes dos cofres (padrão: akv-carga)")
    a.add_argument("--sem-data", type=int, default=15, metavar="PCT",
                   dest="sem_data",
                   help="percentual de chaves sem expiração (padrão: 15)")
    a.add_argument("--paralelismo", type=int, default=24,
                   help="criações simultâneas (padrão: 24)")
    a.add_argument("--rsa", action="store_true",
                   help="usa RSA 2048 em vez de EC P-256 (bem mais lento)")
    a.add_argument("--remover", action="store_true",
                   help="exclui e faz purge dos cofres com o prefixo, e sai")
    a.add_argument("--sim", action="store_true",
                   help="não pede confirmação")
    opcoes = a.parse_args(argv)
    opcoes.cofres = max(1, opcoes.cofres)
    opcoes.chaves = max(1, opcoes.chaves)
    opcoes.paralelismo = max(1, opcoes.paralelismo)
    opcoes.sem_data = min(100, max(0, opcoes.sem_data))
    return opcoes


def confirmar(pergunta, automatico):
    if automatico:
        return True
    if not sys.stdin.isatty():
        print("Entrada não interativa: use --sim para confirmar.", file=sys.stderr)
        return False
    return input(pergunta).strip().lower().startswith("s")


def executar_remocao(cliente, subscription_id, opcoes):
    prefixo = "{}-{}".format(opcoes.prefixo,
                             sufixo_estavel(subscription_id, opcoes.grupo))
    cofres = listar_cofres_do_prefixo(cliente, subscription_id, prefixo)
    if not cofres:
        print("Nenhum cofre com o prefixo '{}' foi encontrado.".format(prefixo))
        return 0

    print("Serão EXCLUÍDOS e purgados {} cofre(s):".format(len(cofres)))
    for cofre in cofres:
        print("  - {}".format(cofre["nome"]))
    if not confirmar("\nConfirma a exclusão? [s/N]: ", opcoes.sim):
        print("Cancelado.")
        return 1

    progresso = Progresso("cofres", len(cofres))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futuros = {
            executor.submit(remover_cofre, cliente, subscription_id,
                            opcoes.grupo, cofre): cofre
            for cofre in cofres
        }
        for futuro in concurrent.futures.as_completed(futuros):
            try:
                futuro.result()
                progresso.avancar()
            except ErroArm as erro:
                progresso.avancar(falhou=True)
                print("\n  ERRO em {}: {}".format(
                    futuros[futuro]["nome"], erro))
    progresso.encerrar()
    print("\nRemoção concluída.")
    return 0


def executar_criacao(cliente, subscription_id, tenant_id, opcoes):
    sufixo = sufixo_estavel(subscription_id, opcoes.grupo)
    nomes_cofres = [
        "{}-{}-{:02d}".format(opcoes.prefixo, sufixo, i + 1)
        for i in range(opcoes.cofres)
    ]
    total_chaves = opcoes.cofres * opcoes.chaves

    print("Serão criados {} cofre(s) com {} chave(s) cada = {} chaves.".format(
        opcoes.cofres, opcoes.chaves, total_chaves))
    print("  Resource group: {} ({})".format(opcoes.grupo, opcoes.local))
    print("  Tipo de chave.: {}".format(
        "RSA 2048" if opcoes.rsa else "EC P-256"))
    print("  Sem expiração.: ~{}%".format(opcoes.sem_data))
    print("  Primeiro cofre: {}".format(nomes_cofres[0]))
    if not confirmar("\nConfirma a criação? [s/N]: ", opcoes.sim):
        print("Cancelado.")
        return 1

    print("\nGarantindo o resource group...")
    garantir_grupo(cliente, subscription_id, opcoes.grupo, opcoes.local)

    print("Criando os cofres...")
    progresso = Progresso("cofres", len(nomes_cofres))
    falhou = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futuros = {
            executor.submit(criar_cofre, cliente, subscription_id, tenant_id,
                            opcoes.grupo, opcoes.local, nome): nome
            for nome in nomes_cofres
        }
        for futuro in concurrent.futures.as_completed(futuros):
            try:
                futuro.result()
                progresso.avancar()
            except ErroArm as erro:
                falhou.append(futuros[futuro])
                progresso.avancar(falhou=True)
                print("\n  ERRO em {}: {}".format(futuros[futuro], erro))
    progresso.encerrar()

    prontos = [n for n in nomes_cofres if n not in falhou]
    if not prontos:
        print("\nNenhum cofre disponível. Abortando.")
        return 2

    print("\nVerificando o que já existe (permite retomar)...")
    tarefas = []
    agora = time.time()
    proporcao = opcoes.sem_data / 100.0
    for nome_cofre in prontos:
        existentes = chaves_existentes(
            cliente, subscription_id, opcoes.grupo, nome_cofre)
        for indice in range(1, opcoes.chaves + 1):
            nome_chave = "chave-{:05d}".format(indice)
            if nome_chave in existentes:
                continue
            tarefas.append(
                (nome_cofre, nome_chave, sortear_expiracao(agora, proporcao))
            )
    print("  {} chave(s) já existiam; {} a criar.".format(
        total_chaves - len(tarefas), len(tarefas)))

    if not tarefas:
        print("\nNada a fazer.")
        return 0

    # Intercala os cofres para não concentrar as escritas num só.
    random.shuffle(tarefas)

    print("\nCriando as chaves...")
    progresso = Progresso("chaves", len(tarefas))
    erros = []

    def trabalho(tarefa):
        nome_cofre, nome_chave, expiracao = tarefa
        criar_chave(cliente, subscription_id, opcoes.grupo, nome_cofre,
                    nome_chave, expiracao, opcoes.rsa)

    with concurrent.futures.ThreadPoolExecutor(max_workers=opcoes.paralelismo) as executor:
        futuros = {executor.submit(trabalho, t): t for t in tarefas}
        for futuro in concurrent.futures.as_completed(futuros):
            try:
                futuro.result()
                progresso.avancar()
            except ErroArm as erro:
                erros.append((futuros[futuro], str(erro)))
                progresso.avancar(falhou=True)
    progresso.encerrar()

    print("\n" + "-" * 60)
    print("  Cofres criados ..... {}".format(len(prontos)))
    print("  Chaves criadas ..... {}".format(len(tarefas) - len(erros)))
    print("  Falhas ............. {}".format(len(erros)))
    print("  Chamadas HTTP ...... {}".format(cliente.requisicoes))
    if erros:
        print("\n  Primeiras falhas:")
        for tarefa, mensagem in erros[:5]:
            print("    {}/{}: {}".format(tarefa[0], tarefa[1], mensagem[:120]))
        print("\n  Rode o comando de novo para criar apenas o que faltou.")
    print("\nPara apagar tudo depois:")
    print(
        "  python3 {} --grupo {} --remover".format(sys.argv[0], opcoes.grupo))
    return 2 if erros else 0


def principal(argv=None):
    opcoes = analisar_argumentos(argv if argv is not None else sys.argv[1:])
    cliente = ClienteArm()
    try:
        subscription_id, tenant_id, nome_sub = contexto_azure()
    except ErroArm as erro:
        print("ERRO: {}".format(erro), file=sys.stderr)
        return 1

    print("=" * 60)
    print(" Massa de teste para o inventario_akv")
    print("=" * 60)
    print("Subscription: {} ({})\n".format(nome_sub, subscription_id))

    try:
        if opcoes.remover:
            return executar_remocao(cliente, subscription_id, opcoes)
        return executar_criacao(cliente, subscription_id, tenant_id, opcoes)
    except ErroArm as erro:
        print("\nERRO: {}".format(erro), file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(principal())
    except KeyboardInterrupt:
        print("\nInterrompido. Rode de novo para continuar de onde parou.")
        sys.exit(130)
