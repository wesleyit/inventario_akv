#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inventário de chaves criptográficas dos Azure Key Vaults de um tenant Azure.

Gera um CSV com as chaves que possuem data de expiração, descartando as chaves
criadas automaticamente por certificados. Usa exclusivamente o plano de
gerenciamento (management.azure.com), o que permite inventariar cofres
protegidos por Private Endpoint, e apenas a biblioteca padrão do Python --
roda no Azure Cloud Shell sem instalar nada.

Como funciona:

  1. O Azure Resource Graph descobre todos os cofres do tenant em poucas
     consultas, sem percorrer subscription por subscription.
  2. As leituras de chaves e segredos viram uma fila única de URLs, drenada em
     lotes de 20 pela API de batch do ARM. Cada lote é uma só chamada HTTP, o
     que reduz em 20x o número de idas e vindas na rede.
  3. Cada lote concluído é gravado num banco SQLite local. Se a sessão do Cloud
     Shell cair no meio, basta rodar de novo: a execução retoma de onde parou.
  4. Os segredos são lidos apenas dos cofres que têm alguma chave com expiração,
     e servem somente para identificar quais chaves pertencem a certificados.
"""

import argparse
import concurrent.futures
import csv
import http.client
import json
import os
import random
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import OrderedDict, deque

# -------------------------------------------------------------------
# Versões de API e endpoints
# -------------------------------------------------------------------
HOST_ARM = "management.azure.com"
BASE_ARM = "https://" + HOST_ARM
API_SUBSCRIPTIONS = "2022-12-01"
API_KEY_VAULT = "2023-07-01"
API_BATCH = "2020-06-01"
API_RESOURCE_GRAPH = "2022-10-01"

# Acima de 20 sub-requisições o ARM responde 202 e exige polling assíncrono.
LOTE_MAXIMO = 20
PAGINA_RESOURCE_GRAPH = 1000

# contentType que identifica um segredo gerado por um certificado
CONTENT_TYPE_CERTIFICADO = "application/x-pkcs12"

# -------------------------------------------------------------------
# Padrões de execução (todos ajustáveis por linha de comando)
# -------------------------------------------------------------------
LOTES_SIMULTANEOS_PADRAO = 4
LOTES_POR_SEGUNDO_PADRAO = 4.0
TENTATIVAS_MAXIMAS = 6
TIMEOUT_HTTP = 90
VALIDADE_RETOMADA_HORAS = 12

# Abaixo destes limites de cota restante o script cede espaço para os demais
# consumidores da subscription em vez de insistir.
COTA_ALERTA = 1000
COTA_CRITICA = 300
PAUSA_ALERTA = 30
PAUSA_CRITICA = 120

ARQUIVO_BANCO = "inventario_akv.db"
ARQUIVO_RELATORIO = "chaves_filtradas.csv"
ARQUIVO_ERROS = "erros.csv"

CAB_RELATORIO = [
    "subscription_id",
    "subscription_nome",
    "resource_group",
    "nome_cofre",
    "nome_chave",
    "data_expiracao",
    "dias_para_expirar",
    "possivel_chave_de_certificado",
]
CAB_ERROS = [
    "tipo",
    "subscription_id",
    "nome_cofre",
    "etapa",
    "status_http",
    "detalhe",
    "ocorrido_em",
]

# Sinalizador global de interrupção (Ctrl+C ou queda da sessão).
_PARAR = threading.Event()


class ErroArm(Exception):
    """Falha ao conversar com o Azure Resource Manager."""

    def __init__(self, mensagem, status=None):
        super().__init__(mensagem)
        self.status = status


# ===================================================================
# Controle de vazão
# ===================================================================
class LimitadorTaxa:
    """Balde de tokens global que limita as chamadas HTTP por segundo.

    Existe para garantir que o inventário nunca consuma a cota de leitura do
    ARM a ponto de prejudicar outros serviços do mesmo tenant.
    """

    def __init__(self, taxa_maxima):
        self._taxa_maxima = float(taxa_maxima)
        self._taxa_minima = max(0.5, self._taxa_maxima / 8.0)
        self._taxa = self._taxa_maxima
        self._capacidade = max(1.0, self._taxa_maxima)
        self._tokens = self._capacidade
        self._atualizado = time.monotonic()
        self._pausado_ate = 0.0
        self._reduzido_em = 0.0
        self._trava = threading.Lock()

    def adquirir(self):
        while not _PARAR.is_set():
            with self._trava:
                agora = time.monotonic()
                if agora < self._pausado_ate:
                    espera = self._pausado_ate - agora
                else:
                    self._recuperar(agora)
                    self._tokens = min(
                        self._capacidade,
                        self._tokens + (agora - self._atualizado) * self._taxa,
                    )
                    self._atualizado = agora
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    espera = (1.0 - self._tokens) / self._taxa
            _dormir(min(espera, 5.0))

    def _recuperar(self, agora):
        """Volta gradualmente à taxa nominal após um período sem throttling."""

        if self._taxa >= self._taxa_maxima or not self._reduzido_em:
            return
        if agora - self._reduzido_em >= 20.0:
            self._taxa = min(self._taxa_maxima, self._taxa * 1.5)
            self._reduzido_em = agora

    def reduzir(self):
        with self._trava:
            self._taxa = max(self._taxa_minima, self._taxa / 2.0)
            self._reduzido_em = time.monotonic()

    def pausar(self, segundos):
        with self._trava:
            self._pausado_ate = max(
                self._pausado_ate, time.monotonic() + max(0.0, segundos)
            )

    def taxa_atual(self):
        with self._trava:
            return self._taxa


class FreioPorSubscription:
    """Pausa as leituras de uma subscription cuja cota do ARM está acabando."""

    def __init__(self):
        self._pausas = {}
        self._trava = threading.Lock()
        self.acionamentos = 0

    def aguardar(self, subscription_id):
        while not _PARAR.is_set():
            with self._trava:
                ate = self._pausas.get(subscription_id, 0.0)
                agora = time.monotonic()
                if agora >= ate:
                    return
                espera = ate - agora
            _dormir(min(espera, 5.0))

    def pausar(self, subscription_id, segundos):
        with self._trava:
            atual = self._pausas.get(subscription_id, 0.0)
            novo = time.monotonic() + max(0.0, segundos)
            if novo > atual:
                self._pausas[subscription_id] = novo
                self.acionamentos += 1

    def avaliar_cota(self, subscription_id, restante):
        if restante is None:
            return
        if restante < COTA_CRITICA:
            self.pausar(subscription_id, PAUSA_CRITICA)
        elif restante < COTA_ALERTA:
            self.pausar(subscription_id, PAUSA_ALERTA)


def _dormir(segundos):
    """Dorme em fatias curtas para responder rápido a uma interrupção."""

    fim = time.monotonic() + max(0.0, segundos)
    while not _PARAR.is_set():
        restante = fim - time.monotonic()
        if restante <= 0:
            return
        time.sleep(min(restante, 0.5))


# ===================================================================
# Cliente do Azure Resource Manager
# ===================================================================
class ClienteArm:
    """Fala com o ARM reaproveitando conexões, com retry e controle de vazão."""

    def __init__(self, limitador, freio):
        self._limitador = limitador
        self._freio = freio
        self._local = threading.local()
        self._token = None
        self._token_expira_em = 0.0
        self._trava_token = threading.Lock()
        self._trava_metricas = threading.Lock()
        self.requisicoes = 0
        self.throttles = 0

    # ---------------------------------------------------------------
    # Autenticação
    # ---------------------------------------------------------------
    def obter_token(self):
        with self._trava_token:
            if self._token and time.time() < self._token_expira_em:
                return self._token
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
                raise ErroArm(
                    "comando 'az' não encontrado. Rode este script no Azure "
                    "Cloud Shell ou instale o Azure CLI."
                )
            except subprocess.CalledProcessError as erro:
                raise ErroArm(
                    "não foi possível obter o token de acesso. Verifique se "
                    "você está logado com 'az login'.\n" + (erro.stderr or "")
                )
            self._token = json.loads(resultado.stdout)["accessToken"]
            self._token_expira_em = time.time() + 25 * 60
            return self._token

    def invalidar_token(self):
        with self._trava_token:
            self._token = None
            self._token_expira_em = 0.0

    # ---------------------------------------------------------------
    # Conexões persistentes (uma por thread, por host)
    # ---------------------------------------------------------------
    def _conexao(self, host):
        conexoes = getattr(self._local, "conexoes", None)
        if conexoes is None:
            conexoes = {}
            self._local.conexoes = conexoes
        conexao = conexoes.get(host)
        if conexao is None:
            conexao = http.client.HTTPSConnection(host, timeout=TIMEOUT_HTTP)
            conexoes[host] = conexao
        return conexao

    def _descartar_conexao(self, host):
        conexoes = getattr(self._local, "conexoes", None) or {}
        conexao = conexoes.pop(host, None)
        if conexao is not None:
            try:
                conexao.close()
            except Exception:
                pass

    # ---------------------------------------------------------------
    # Requisição com retry
    # ---------------------------------------------------------------
    def requisitar(self, metodo, url, corpo=None, subscription_id=None):
        partes = urllib.parse.urlsplit(url)
        host = partes.netloc or HOST_ARM
        caminho = partes.path + (("?" + partes.query) if partes.query else "")
        dados = json.dumps(corpo).encode(
            "utf-8") if corpo is not None else None
        ultimo = "causa desconhecida"

        for tentativa in range(1, TENTATIVAS_MAXIMAS + 1):
            if _PARAR.is_set():
                raise ErroArm("execução interrompida")

            if subscription_id:
                self._freio.aguardar(subscription_id)
            self._limitador.adquirir()
            if _PARAR.is_set():
                raise ErroArm("execução interrompida")

            cabecalhos = {
                "Authorization": "Bearer " + self.obter_token(),
                "Accept": "application/json",
            }
            if dados is not None:
                cabecalhos["Content-Type"] = "application/json"

            try:
                conexao = self._conexao(host)
                conexao.request(metodo, caminho, body=dados,
                                headers=cabecalhos)
                resposta = conexao.getresponse()
                bruto = resposta.read()
                status = resposta.status
                cabecalhos_resposta = {
                    nome.lower(): valor for nome, valor in resposta.getheaders()
                }
            except Exception as erro:
                self._descartar_conexao(host)
                ultimo = "falha de rede: {}".format(erro)
                _dormir(self._espera(tentativa))
                continue

            with self._trava_metricas:
                self.requisicoes += 1
            self._avaliar_cota(cabecalhos_resposta, subscription_id)

            if 200 <= status < 300:
                if not bruto:
                    return {}
                return json.loads(bruto.decode("utf-8"))

            detalhe = bruto.decode("utf-8", "replace").strip()[:300]

            if status == 401:
                self.invalidar_token()
                ultimo = "token recusado (401)"
                continue

            if status == 429 or status >= 500:
                if status == 429:
                    with self._trava_metricas:
                        self.throttles += 1
                    self._limitador.reduzir()
                espera = self._retry_after(cabecalhos_resposta)
                if espera is None:
                    espera = self._espera(tentativa)
                if status == 429:
                    self._limitador.pausar(espera)
                    if subscription_id:
                        self._freio.pausar(subscription_id, espera)
                ultimo = "HTTP {} -- {}".format(status, detalhe)
                _dormir(espera)
                continue

            raise ErroArm(
                "HTTP {} -- {}".format(status, detalhe), status=status)

        raise ErroArm(
            "falhou após {} tentativas -- {}".format(
                TENTATIVAS_MAXIMAS, ultimo)
        )

    @staticmethod
    def _espera(tentativa):
        return min(60.0, 2.0 ** (tentativa - 1)) + random.uniform(0.0, 1.0)

    @staticmethod
    def _retry_after(cabecalhos):
        valor = cabecalhos.get("retry-after")
        if not valor:
            return None
        try:
            return max(1.0, float(valor))
        except (TypeError, ValueError):
            return None

    def _avaliar_cota(self, cabecalhos, subscription_id):
        if not subscription_id:
            return
        valor = cabecalhos.get("x-ms-ratelimit-remaining-subscription-reads")
        if valor is None:
            return
        try:
            self._freio.avaliar_cota(subscription_id, int(valor))
        except (TypeError, ValueError):
            pass

    # ---------------------------------------------------------------
    # Batch
    # ---------------------------------------------------------------
    def executar_lote(self, tarefas):
        """Envia até 20 GETs numa única chamada HTTP.

        Devolve (pares, faltantes): os pares casados tarefa/resposta e as
        tarefas que o ARM não respondeu e que precisam voltar para a fila.
        """

        requisicoes = []
        for tarefa in tarefas:
            tarefa["nome_requisicao"] = uuid.uuid4().hex
            requisicoes.append(
                {
                    "httpMethod": "GET",
                    "name": tarefa["nome_requisicao"],
                    "url": tarefa["url"],
                }
            )

        url = "{}/batch?api-version={}".format(BASE_ARM, API_BATCH)
        corpo = self.requisitar("POST", url, {"requests": requisicoes})
        respostas = corpo.get("responses") or []

        por_nome = {t["nome_requisicao"]: t for t in tarefas}
        pares = []
        atendidas = set()
        for indice, resposta in enumerate(respostas):
            tarefa = por_nome.get(resposta.get("name"))
            if tarefa is None and indice < len(tarefas):
                # Correlação posicional: rede de segurança caso o ARM omita o
                # campo 'name' na resposta.
                tarefa = tarefas[indice]
            if tarefa is None or id(tarefa) in atendidas:
                continue
            atendidas.add(id(tarefa))
            pares.append((tarefa, resposta))

        faltantes = [t for t in tarefas if id(t) not in atendidas]
        return pares, faltantes


# ===================================================================
# Fila de tarefas
# ===================================================================
class FilaTarefas:
    """Fila que entrega tarefas alternando entre subscriptions.

    Distribuir cada lote entre subscriptions diferentes espalha o consumo de
    cota do ARM, em vez de esgotar o balde de uma subscription por vez.
    """

    def __init__(self):
        self._por_subscription = OrderedDict()
        self._total = 0

    def adicionar(self, tarefa):
        fila = self._por_subscription.get(tarefa["subscription_id"])
        if fila is None:
            fila = deque()
            self._por_subscription[tarefa["subscription_id"]] = fila
        fila.append(tarefa)
        self._total += 1

    def retirar(self, quantidade):
        lote = []
        while len(lote) < quantidade and self._total:
            for subscription_id in list(self._por_subscription.keys()):
                if len(lote) >= quantidade:
                    break
                fila = self._por_subscription[subscription_id]
                if not fila:
                    del self._por_subscription[subscription_id]
                    continue
                lote.append(fila.popleft())
                self._total -= 1
        return lote

    def __len__(self):
        return self._total


# ===================================================================
# Progresso
# ===================================================================
class Progresso:
    """Mostra andamento agregado, mantendo o terminal ativo."""

    def __init__(self, rotulo, total, concluidos=0):
        self.rotulo = rotulo
        self.total = max(1, total)
        self.concluidos = concluidos
        self.erros = 0
        self._inicio = time.monotonic()
        self._ultimo_desenho = self._inicio
        self._interativo = sys.stdout.isatty()

    def avancar(self, quantidade=1):
        self.concluidos += quantidade

    def registrar_erro(self):
        self.erros += 1

    def desenhar(self, forcar=False, sufixo=""):
        agora = time.monotonic()
        intervalo = 1.0 if self._interativo else 15.0
        if not forcar and agora - self._ultimo_desenho < intervalo:
            return
        self._ultimo_desenho = agora

        fracao = min(1.0, self.concluidos / float(self.total))
        decorrido = agora - self._inicio
        if self.concluidos and fracao < 1.0:
            restante = decorrido / max(fracao, 1e-9) - decorrido
            estimativa = _formatar_duracao(restante)
        else:
            estimativa = "--:--"

        linha = "  [{:3.0f}%] {} {}/{} | {} erro(s) | decorrido {} | restam ~{}{}".format(
            fracao * 100,
            self.rotulo,
            self.concluidos,
            self.total,
            self.erros,
            _formatar_duracao(decorrido),
            estimativa,
            sufixo,
        )
        if self._interativo:
            sys.stdout.write("\r" + linha.ljust(110)[:110])
        else:
            sys.stdout.write(linha + "\n")
        sys.stdout.flush()

    def encerrar(self):
        self.desenhar(forcar=True)
        if self._interativo:
            sys.stdout.write("\n")
        sys.stdout.flush()


def _formatar_duracao(segundos):
    segundos = int(max(0, segundos))
    if segundos >= 3600:
        return "{:d}h{:02d}m".format(segundos // 3600, (segundos % 3600) // 60)
    return "{:02d}:{:02d}".format(segundos // 60, segundos % 60)


# ===================================================================
# Armazenamento (SQLite) -- usado apenas pela thread principal
# ===================================================================
class Armazenamento:
    def __init__(self, caminho):
        self.caminho = caminho
        self._conexao = sqlite3.connect(caminho)
        self._conexao.execute("PRAGMA journal_mode=WAL")
        self._conexao.execute("PRAGMA synchronous=NORMAL")
        self._criar_esquema()

    def _criar_esquema(self):
        self._conexao.executescript(
            """
            CREATE TABLE IF NOT EXISTS varredura (
                scan_id        TEXT PRIMARY KEY,
                iniciada_em    TEXT NOT NULL,
                iniciada_epoch REAL NOT NULL,
                concluida_em   TEXT
            );
            CREATE TABLE IF NOT EXISTS subscription (
                scan_id         TEXT NOT NULL,
                subscription_id TEXT NOT NULL,
                nome            TEXT,
                PRIMARY KEY (scan_id, subscription_id)
            );
            CREATE TABLE IF NOT EXISTS cofre_etapa (
                scan_id          TEXT NOT NULL,
                vault_id         TEXT NOT NULL,
                etapa            TEXT NOT NULL,
                itens_total      INTEGER NOT NULL DEFAULT 0,
                itens_relevantes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (scan_id, vault_id, etapa)
            );
            CREATE TABLE IF NOT EXISTS chave (
                scan_id         TEXT NOT NULL,
                vault_id        TEXT NOT NULL,
                subscription_id TEXT NOT NULL,
                resource_group  TEXT NOT NULL,
                nome_cofre      TEXT NOT NULL,
                nome_chave      TEXT NOT NULL,
                exp_epoch       INTEGER NOT NULL,
                tem_exportable  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chave ON chave (scan_id, vault_id);
            CREATE TABLE IF NOT EXISTS segredo_certificado (
                scan_id     TEXT NOT NULL,
                vault_id    TEXT NOT NULL,
                nome_secret TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_segredo
                ON segredo_certificado (scan_id, vault_id, nome_secret);
            CREATE TABLE IF NOT EXISTS erro (
                scan_id         TEXT NOT NULL,
                tipo            TEXT NOT NULL,
                subscription_id TEXT,
                nome_cofre      TEXT,
                etapa           TEXT,
                status_http     TEXT,
                detalhe         TEXT,
                ocorrido_em     TEXT NOT NULL
            );
            """
        )
        self._conexao.commit()

    # -- ciclo de vida da varredura ---------------------------------
    def varredura_aberta(self):
        linha = self._conexao.execute(
            "SELECT scan_id, iniciada_em, iniciada_epoch FROM varredura "
            "WHERE concluida_em IS NULL ORDER BY iniciada_epoch DESC LIMIT 1"
        ).fetchone()
        if not linha:
            return None
        return {"scan_id": linha[0], "iniciada_em": linha[1], "iniciada_epoch": linha[2]}

    def iniciar_varredura(self):
        scan_id = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        self._conexao.execute(
            "INSERT OR REPLACE INTO varredura "
            "(scan_id, iniciada_em, iniciada_epoch, concluida_em) VALUES (?,?,?,NULL)",
            (scan_id, _agora_iso(), time.time()),
        )
        self._conexao.commit()
        return scan_id

    def concluir_varredura(self, scan_id):
        self._conexao.execute(
            "UPDATE varredura SET concluida_em = ? WHERE scan_id = ?",
            (_agora_iso(), scan_id),
        )
        self._conexao.commit()

    def descartar_tudo(self):
        for tabela in (
            "varredura",
            "subscription",
            "cofre_etapa",
            "chave",
            "segredo_certificado",
            "erro",
        ):
            self._conexao.execute("DELETE FROM " + tabela)
        self._conexao.commit()

    def descartar_outras_varreduras(self, scan_id):
        for tabela in (
            "subscription",
            "cofre_etapa",
            "chave",
            "segredo_certificado",
            "erro",
        ):
            self._conexao.execute(
                "DELETE FROM {} WHERE scan_id <> ?".format(tabela), (scan_id,)
            )
        self._conexao.execute(
            "DELETE FROM varredura WHERE scan_id <> ?", (scan_id,))
        self._conexao.commit()

    # -- dados ------------------------------------------------------
    def registrar_subscriptions(self, scan_id, subscriptions):
        self._conexao.executemany(
            "INSERT OR REPLACE INTO subscription (scan_id, subscription_id, nome) "
            "VALUES (?,?,?)",
            [(scan_id, s["subscription_id"], s["nome"])
             for s in subscriptions],
        )
        self._conexao.commit()

    def etapas_concluidas(self, scan_id, etapa):
        return {
            linha[0]
            for linha in self._conexao.execute(
                "SELECT vault_id FROM cofre_etapa WHERE scan_id = ? AND etapa = ?",
                (scan_id, etapa),
            )
        }

    def limpar_etapa_incompleta(self, scan_id, etapa, vault_id):
        tabela = "chave" if etapa == "chaves" else "segredo_certificado"
        self._conexao.execute(
            "DELETE FROM {} WHERE scan_id = ? AND vault_id = ?".format(tabela),
            (scan_id, vault_id),
        )

    def gravar_chaves(self, scan_id, linhas):
        if linhas:
            self._conexao.executemany(
                "INSERT INTO chave (scan_id, vault_id, subscription_id, "
                "resource_group, nome_cofre, nome_chave, exp_epoch, tem_exportable) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [(scan_id,) + linha for linha in linhas],
            )

    def gravar_segredos(self, scan_id, linhas):
        if linhas:
            self._conexao.executemany(
                "INSERT INTO segredo_certificado (scan_id, vault_id, nome_secret) "
                "VALUES (?,?,?)",
                [(scan_id,) + linha for linha in linhas],
            )

    def marcar_etapa(self, scan_id, vault_id, etapa, total, relevantes):
        self._conexao.execute(
            "INSERT OR REPLACE INTO cofre_etapa "
            "(scan_id, vault_id, etapa, itens_total, itens_relevantes) VALUES (?,?,?,?,?)",
            (scan_id, vault_id, etapa, total, relevantes),
        )

    def registrar_erro(self, scan_id, tipo, subscription_id, nome_cofre, etapa,
                       status_http, detalhe):
        self._conexao.execute(
            "INSERT INTO erro (scan_id, tipo, subscription_id, nome_cofre, etapa, "
            "status_http, detalhe, ocorrido_em) VALUES (?,?,?,?,?,?,?,?)",
            (
                scan_id,
                tipo,
                subscription_id,
                nome_cofre,
                etapa,
                str(status_http) if status_http is not None else "",
                (detalhe or "")[:500],
                _agora_iso(),
            ),
        )

    def confirmar(self):
        self._conexao.commit()

    # -- consultas de saída -----------------------------------------
    def cofres_com_chaves_expiraveis(self, scan_id):
        return {
            linha[0]
            for linha in self._conexao.execute(
                "SELECT DISTINCT vault_id FROM chave WHERE scan_id = ?", (
                    scan_id,)
            )
        }

    def relatorio(self, scan_id):
        return self._conexao.execute(
            """
            SELECT c.subscription_id,
                   COALESCE(s.nome, ''),
                   c.resource_group,
                   c.nome_cofre,
                   c.nome_chave,
                   c.exp_epoch,
                   c.tem_exportable
              FROM chave c
              LEFT JOIN subscription s
                     ON s.scan_id = c.scan_id
                    AND s.subscription_id = c.subscription_id
             WHERE c.scan_id = ?
               AND NOT EXISTS (
                     SELECT 1 FROM segredo_certificado g
                      WHERE g.scan_id = c.scan_id
                        AND g.vault_id = c.vault_id
                        AND g.nome_secret = c.nome_chave
                   )
             ORDER BY c.exp_epoch ASC, c.nome_cofre, c.nome_chave
            """,
            (scan_id,),
        )

    def erros(self, scan_id):
        return self._conexao.execute(
            "SELECT tipo, subscription_id, nome_cofre, etapa, status_http, "
            "detalhe, ocorrido_em FROM erro WHERE scan_id = ? ORDER BY ocorrido_em",
            (scan_id,),
        )

    def contar_erros(self, scan_id):
        linha = self._conexao.execute(
            "SELECT SUM(tipo = 'erro'), SUM(tipo = 'aviso') FROM erro WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        return (linha[0] or 0), (linha[1] or 0)

    def totais(self, scan_id):
        linha = self._conexao.execute(
            "SELECT COALESCE(SUM(itens_total), 0), COALESCE(SUM(itens_relevantes), 0) "
            "FROM cofre_etapa WHERE scan_id = ? AND etapa = 'chaves'",
            (scan_id,),
        ).fetchone()
        return linha[0], linha[1]

    def fechar(self):
        self._conexao.close()


def _agora_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _epoch_para_iso(epoch):
    return time.strftime("%Y-%m-%d", time.gmtime(int(epoch)))


# ===================================================================
# Descoberta
# ===================================================================
def descobrir_subscriptions(cliente):
    """Lista as subscriptions do tenant (usadas para nomear e conferir escopo)."""

    url = "{}/subscriptions?api-version={}".format(BASE_ARM, API_SUBSCRIPTIONS)
    subscriptions = []
    while url:
        corpo = cliente.requisitar("GET", url)
        for item in corpo.get("value") or []:
            if item.get("state") in ("Disabled", "Deleted"):
                continue
            subscriptions.append(
                {
                    "subscription_id": item.get("subscriptionId", ""),
                    "nome": item.get("displayName", ""),
                }
            )
        url = corpo.get("nextLink")
    return subscriptions


def _consultar_resource_graph(cliente, consulta):
    """Roda uma consulta KQL no Resource Graph, tratando a paginação."""

    url = "{}/providers/Microsoft.ResourceGraph/resources?api-version={}".format(
        BASE_ARM, API_RESOURCE_GRAPH
    )
    registros = []
    skip_token = None
    while True:
        opcoes = {"resultFormat": "objectArray", "$top": PAGINA_RESOURCE_GRAPH}
        if skip_token:
            opcoes["$skipToken"] = skip_token
        corpo = cliente.requisitar(
            "POST", url, {"query": consulta, "options": opcoes})

        if str(corpo.get("resultTruncated", "")).lower() == "true":
            raise ErroArm(
                "o Resource Graph truncou o resultado; o inventário ficaria "
                "incompleto e a execução foi abortada por segurança"
            )

        registros.extend(corpo.get("data") or [])
        skip_token = corpo.get("$skipToken")
        if not skip_token:
            return registros


def descobrir_cofres(cliente):
    """Descobre todos os Key Vaults do tenant numa única consulta paginada."""

    consulta = (
        "resources "
        "| where type =~ 'microsoft.keyvault/vaults' "
        "| project id, nome = name, subscriptionId, resourceGroup "
        "| order by id asc"
    )
    cofres = []
    for registro in _consultar_resource_graph(cliente, consulta):
        identificador = registro.get("id") or ""
        if not identificador:
            continue
        cofres.append(
            {
                "vault_id": identificador.lower(),
                "subscription_id": registro.get("subscriptionId", ""),
                "resource_group": registro.get("resourceGroup", ""),
                "nome_cofre": registro.get("nome", ""),
            }
        )
    return cofres


def conferir_cobertura(cliente, subscriptions):
    """Compara o que o Resource Graph enxerga com o que o ARM lista.

    Divergência significa que parte do tenant está fora do alcance da
    identidade autenticada -- e um inventário de compliance não pode ficar
    silenciosamente incompleto.
    """

    try:
        registros = _consultar_resource_graph(
            cliente,
            "resourcecontainers "
            "| where type =~ 'microsoft.resources/subscriptions' "
            "| project subscriptionId "
            "| order by subscriptionId asc",
        )
    except ErroArm:
        return None
    return len({r.get("subscriptionId") for r in registros if r.get("subscriptionId")})


# ===================================================================
# Varredura em lotes
# ===================================================================
def _montar_url(cofre, etapa):
    return (
        "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault"
        "/vaults/{}/{}?api-version={}".format(
            BASE_ARM,
            urllib.parse.quote(cofre["subscription_id"]),
            urllib.parse.quote(cofre["resource_group"]),
            urllib.parse.quote(cofre["nome_cofre"]),
            "keys" if etapa == "chaves" else "secrets",
            API_KEY_VAULT,
        )
    )


def _nova_tarefa(cofre, etapa, url=None):
    return {
        "vault_id": cofre["vault_id"],
        "subscription_id": cofre["subscription_id"],
        "resource_group": cofre["resource_group"],
        "nome_cofre": cofre["nome_cofre"],
        "etapa": etapa,
        "url": url or _montar_url(cofre, etapa),
        "total": 0,
        "relevantes": 0,
        "tentativas_lote": 0,
    }


def _converter_chaves(tarefa, itens):
    """Mantém apenas as chaves com data de expiração -- o objeto do relatório."""

    linhas = []
    for item in itens:
        atributos = (item.get("properties") or {}).get("attributes") or {}
        expiracao = atributos.get("exp")
        if expiracao is None:
            continue
        linhas.append(
            (
                tarefa["vault_id"],
                tarefa["subscription_id"],
                tarefa["resource_group"],
                tarefa["nome_cofre"],
                item.get("name", ""),
                int(expiracao),
                1 if "exportable" in atributos else 0,
            )
        )
    return linhas


def _converter_segredos(tarefa, itens):
    """Guarda apenas os segredos de certificado, que é o que exclui uma chave."""

    linhas = []
    for item in itens:
        tipo = (item.get("properties") or {}).get("contentType") or ""
        if tipo.strip().lower() == CONTENT_TYPE_CERTIFICADO:
            linhas.append((tarefa["vault_id"], item.get("name", "")))
    return linhas


def executar_etapa(cliente, armazenamento, scan_id, cofres, etapa, opcoes, rotulo):
    """Drena a fila de URLs da etapa em lotes, gravando cada lote concluído."""

    concluidos = armazenamento.etapas_concluidas(scan_id, etapa)
    pendentes = [c for c in cofres if c["vault_id"] not in concluidos]

    for cofre in pendentes:
        # Um cofre interrompido pode ter deixado páginas soltas da execução
        # anterior; recomeça limpo para não duplicar nem misturar.
        armazenamento.limpar_etapa_incompleta(
            scan_id, etapa, cofre["vault_id"])
    armazenamento.confirmar()

    progresso = Progresso(rotulo, len(cofres), len(concluidos))
    if not pendentes:
        progresso.encerrar()
        return progresso

    fila = FilaTarefas()
    for cofre in pendentes:
        fila.adicionar(_nova_tarefa(cofre, etapa))

    gravar = (
        armazenamento.gravar_chaves if etapa == "chaves" else armazenamento.gravar_segredos
    )
    converter = _converter_chaves if etapa == "chaves" else _converter_segredos

    em_voo = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=opcoes.lotes, thread_name_prefix="lote"
    ) as executor:
        while True:
            while len(fila) and len(em_voo) < opcoes.lotes and not _PARAR.is_set():
                lote = fila.retirar(LOTE_MAXIMO)
                if not lote:
                    break
                em_voo[executor.submit(cliente.executar_lote, lote)] = lote

            if not em_voo:
                break

            concluidas, _ = concurrent.futures.wait(
                em_voo, return_when=concurrent.futures.FIRST_COMPLETED
            )

            for futuro in concluidas:
                lote = em_voo.pop(futuro)
                try:
                    pares, faltantes = futuro.result()
                except ErroArm as erro:
                    _tratar_lote_falho(
                        armazenamento, scan_id, fila, lote, erro, progresso
                    )
                    continue

                for tarefa in faltantes:
                    _reenfileirar(
                        armazenamento, scan_id, fila, tarefa,
                        "o ARM não devolveu resposta para esta requisição no lote",
                        progresso,
                    )

                for tarefa, resposta in pares:
                    _tratar_resposta(
                        armazenamento, scan_id, fila, tarefa, resposta,
                        converter, gravar, progresso,
                    )

            armazenamento.confirmar()
            progresso.desenhar(sufixo=" | {} req".format(cliente.requisicoes))

            if _PARAR.is_set() and not em_voo:
                break

    armazenamento.confirmar()
    progresso.encerrar()
    return progresso


def _tratar_resposta(armazenamento, scan_id, fila, tarefa, resposta, converter,
                     gravar, progresso):
    status = resposta.get("httpStatusCode")
    conteudo = resposta.get("content") or {}

    if status == 200:
        itens = conteudo.get("value") or []
        tarefa["total"] += len(itens)
        linhas = converter(tarefa, itens)
        tarefa["relevantes"] += len(linhas)
        gravar(scan_id, linhas)

        proxima = conteudo.get("nextLink")
        if proxima:
            # Paginação sem laço aninhado: a próxima página é só mais uma
            # tarefa na mesma fila.
            continuacao = dict(tarefa)
            continuacao["url"] = proxima
            continuacao["tentativas_lote"] = 0
            fila.adicionar(continuacao)
        else:
            armazenamento.marcar_etapa(
                scan_id, tarefa["vault_id"], tarefa["etapa"],
                tarefa["total"], tarefa["relevantes"],
            )
            progresso.avancar()
        return

    detalhe = json.dumps(conteudo.get("error") or conteudo)[:300]

    if status == 404:
        armazenamento.registrar_erro(
            scan_id, "aviso", tarefa["subscription_id"], tarefa["nome_cofre"],
            tarefa["etapa"], status,
            "cofre não encontrado -- provavelmente removido durante a varredura",
        )
        armazenamento.marcar_etapa(
            scan_id, tarefa["vault_id"], tarefa["etapa"], 0, 0
        )
        progresso.avancar()
        return

    if status == 429 or (isinstance(status, int) and status >= 500):
        _reenfileirar(
            armazenamento, scan_id, fila, tarefa,
            "HTTP {} -- {}".format(status, detalhe), progresso, status,
        )
        return

    armazenamento.registrar_erro(
        scan_id, "erro", tarefa["subscription_id"], tarefa["nome_cofre"],
        tarefa["etapa"], status, detalhe,
    )
    progresso.registrar_erro()
    progresso.avancar()


def _reenfileirar(armazenamento, scan_id, fila, tarefa, motivo, progresso, status=None):
    tarefa["tentativas_lote"] = tarefa.get("tentativas_lote", 0) + 1
    if tarefa["tentativas_lote"] <= 3:
        fila.adicionar(tarefa)
        return
    armazenamento.registrar_erro(
        scan_id, "erro", tarefa["subscription_id"], tarefa["nome_cofre"],
        tarefa["etapa"], status, "desistiu após 3 reenvios -- " + motivo,
    )
    progresso.registrar_erro()
    progresso.avancar()


def _tratar_lote_falho(armazenamento, scan_id, fila, lote, erro, progresso):
    for tarefa in lote:
        _reenfileirar(armazenamento, scan_id, fila,
                      tarefa, str(erro), progresso)


# ===================================================================
# Saída
# ===================================================================
def exportar_relatorio(armazenamento, scan_id, caminho, dias_limite):
    agora = time.time()
    total = 0
    suspeitas = 0
    with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(CAB_RELATORIO)
        for linha in armazenamento.relatorio(scan_id):
            (subscription_id, subscription_nome, resource_group, nome_cofre,
             nome_chave, exp_epoch, tem_exportable) = linha
            dias = int((exp_epoch - agora) // 86400)
            if dias_limite is not None and dias > dias_limite:
                continue
            suspeita = "sim" if not tem_exportable else ""
            if suspeita:
                suspeitas += 1
            escritor.writerow(
                [
                    subscription_id,
                    subscription_nome,
                    resource_group,
                    nome_cofre,
                    nome_chave,
                    _epoch_para_iso(exp_epoch),
                    dias,
                    suspeita,
                ]
            )
            total += 1
    return total, suspeitas


def exportar_erros(armazenamento, scan_id, caminho):
    linhas = list(armazenamento.erros(scan_id))
    if not linhas:
        if os.path.exists(caminho):
            os.remove(caminho)
        return 0
    with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(CAB_ERROS)
        escritor.writerows(linhas)
    return len(linhas)


# ===================================================================
# Retomada
# ===================================================================
def decidir_varredura(armazenamento, opcoes):
    """Decide entre retomar uma execução interrompida ou começar do zero.

    Um inventário antigo é pior que nenhum: chaves nascem todo dia, então
    retomar algo de dias atrás produziria um relatório que mistura épocas.
    """

    aberta = armazenamento.varredura_aberta()
    if not aberta:
        return armazenamento.iniciar_varredura(), False

    idade_horas = (time.time() - aberta["iniciada_epoch"]) / 3600.0
    recente = idade_horas <= VALIDADE_RETOMADA_HORAS

    if opcoes.recomecar:
        retomar = False
    elif opcoes.continuar:
        retomar = True
    elif not sys.stdin.isatty():
        retomar = recente
    else:
        print(
            "\nEncontrei uma varredura interrompida de {} ({:.1f}h atrás).".format(
                aberta["iniciada_em"], idade_horas
            ),
            flush=True,
        )
        if recente:
            padrao, texto = True, "[C] continuar (padrão) / [R] recomeçar: "
        else:
            print(
                "  Ela está desatualizada -- chaves criadas depois disso não "
                "apareceriam no relatório.",
                flush=True,
            )
            padrao, texto = False, "[R] recomeçar (padrão) / [C] continuar: "
        resposta = input(texto).strip().lower()
        if resposta.startswith("c"):
            retomar = True
        elif resposta.startswith("r"):
            retomar = False
        else:
            retomar = padrao

    if retomar:
        print("Retomando a varredura {}.\n".format(
            aberta["scan_id"]), flush=True)
        return aberta["scan_id"], True

    armazenamento.descartar_tudo()
    scan_id = armazenamento.iniciar_varredura()
    print("Começando uma varredura nova ({}).\n".format(scan_id), flush=True)
    return scan_id, False


# ===================================================================
# MAIN
# ===================================================================
def analisar_argumentos(argv):
    analisador = argparse.ArgumentParser(
        description="Inventaria as chaves dos Azure Key Vaults de um tenant, "
        "listando apenas as que têm data de expiração e não pertencem a "
        "certificados.",
    )
    analisador.add_argument(
        "--saida", default=".", metavar="PASTA",
        help="pasta onde gravar o CSV e o banco de retomada (padrão: pasta atual)",
    )
    analisador.add_argument(
        "--dias", type=int, default=None, metavar="N",
        help="lista apenas chaves que vencem em até N dias (padrão: todas)",
    )
    analisador.add_argument(
        "--lotes", type=int, default=LOTES_SIMULTANEOS_PADRAO, metavar="N",
        help="lotes simultâneos (padrão: {})".format(LOTES_SIMULTANEOS_PADRAO),
    )
    analisador.add_argument(
        "--lotes-por-segundo", type=float, default=LOTES_POR_SEGUNDO_PADRAO,
        metavar="N", dest="lotes_por_segundo",
        help="teto de chamadas HTTP por segundo (padrão: {})".format(
            LOTES_POR_SEGUNDO_PADRAO
        ),
    )
    grupo = analisador.add_mutually_exclusive_group()
    grupo.add_argument(
        "--continuar", action="store_true",
        help="retoma a varredura interrompida sem perguntar",
    )
    grupo.add_argument(
        "--recomecar", action="store_true",
        help="descarta a varredura anterior e começa do zero sem perguntar",
    )
    opcoes = analisador.parse_args(argv)
    opcoes.lotes = max(1, opcoes.lotes)
    opcoes.lotes_por_segundo = max(0.5, opcoes.lotes_por_segundo)
    return opcoes


def principal(argv=None):
    opcoes = analisar_argumentos(argv if argv is not None else sys.argv[1:])

    pasta = os.path.abspath(os.path.expanduser(opcoes.saida))
    os.makedirs(pasta, exist_ok=True)
    caminho_banco = os.path.join(pasta, ARQUIVO_BANCO)
    caminho_relatorio = os.path.join(pasta, ARQUIVO_RELATORIO)
    caminho_erros = os.path.join(pasta, ARQUIVO_ERROS)

    print("=" * 64, flush=True)
    print(" Inventário de chaves dos Azure Key Vaults", flush=True)
    print("=" * 64, flush=True)
    print("Resultados em: {}".format(pasta), flush=True)
    if pasta.startswith("/tmp"):
        print(
            "AVISO: /tmp não sobrevive ao fim da sessão do Cloud Shell. "
            "Prefira uma pasta dentro do seu diretório pessoal.",
            flush=True,
        )

    limitador = LimitadorTaxa(opcoes.lotes_por_segundo)
    freio = FreioPorSubscription()
    cliente = ClienteArm(limitador, freio)
    armazenamento = Armazenamento(caminho_banco)
    inicio = time.monotonic()
    interrompido = False

    try:
        cliente.obter_token()
    except ErroArm as erro:
        print("\nERRO: {}".format(erro), file=sys.stderr)
        armazenamento.fechar()
        return 1

    scan_id, retomada = decidir_varredura(armazenamento, opcoes)
    armazenamento.descartar_outras_varreduras(scan_id)

    try:
        print("Listando subscriptions...", flush=True)
        subscriptions = descobrir_subscriptions(cliente)
        armazenamento.registrar_subscriptions(scan_id, subscriptions)
        print("  {} subscription(s) ativa(s).".format(
            len(subscriptions)), flush=True)

        vistas = conferir_cobertura(cliente, subscriptions)
        if vistas is not None and vistas < len(subscriptions):
            print(
                "  AVISO: o Resource Graph enxerga {} de {} subscriptions. "
                "Cofres nas demais não entrarão no relatório -- verifique se a "
                "sua conta tem permissão de leitura em todo o tenant.".format(
                    vistas, len(subscriptions)
                ),
                flush=True,
            )

        print("\nDescobrindo Key Vaults (Azure Resource Graph)...", flush=True)
        cofres = descobrir_cofres(cliente)
        print("  {} Key Vault(s) encontrados.".format(len(cofres)), flush=True)

        if not cofres:
            print("\nNenhum Key Vault acessível. Nada a inventariar.", flush=True)
            armazenamento.concluir_varredura(scan_id)
            armazenamento.fechar()
            return 0

        print("\nLendo chaves (lotes de {} por chamada)...".format(
            LOTE_MAXIMO), flush=True)
        executar_etapa(
            cliente, armazenamento, scan_id, cofres, "chaves", opcoes, "cofres"
        )

        candidatos = armazenamento.cofres_com_chaves_expiraveis(scan_id)
        cofres_candidatos = [c for c in cofres if c["vault_id"] in candidatos]
        print(
            "\nLendo segredos dos {} cofre(s) que têm chaves com expiração...".format(
                len(cofres_candidatos)
            ),
            flush=True,
        )
        if cofres_candidatos:
            executar_etapa(
                cliente, armazenamento, scan_id, cofres_candidatos, "secrets",
                opcoes, "cofres",
            )

    except KeyboardInterrupt:
        _PARAR.set()
        interrompido = True
        print("\n\nInterrompido. O progresso foi salvo.", flush=True)
    except ErroArm as erro:
        _PARAR.set()
        interrompido = True
        print("\n\nERRO: {}".format(erro), file=sys.stderr)

    armazenamento.confirmar()

    print("\nGerando o relatório...", flush=True)
    total, suspeitas = exportar_relatorio(
        armazenamento, scan_id, caminho_relatorio, opcoes.dias
    )
    qtd_erros = exportar_erros(armazenamento, scan_id, caminho_erros)
    erros, avisos = armazenamento.contar_erros(scan_id)
    chaves_vistas, chaves_com_data = armazenamento.totais(scan_id)

    if not interrompido and erros == 0:
        armazenamento.concluir_varredura(scan_id)

    print("\n" + "-" * 64, flush=True)
    print(" Resumo", flush=True)
    print("-" * 64, flush=True)
    print("  Chaves examinadas ............ {}".format(chaves_vistas), flush=True)
    print("  Com data de expiração ........ {}".format(
        chaves_com_data), flush=True)
    print("  No relatório final ........... {}".format(total), flush=True)
    if opcoes.dias is not None:
        print("    (apenas as que vencem em até {} dias)".format(
            opcoes.dias), flush=True)
    print(
        "  Chamadas HTTP ................ {} (throttling: {})".format(
            cliente.requisicoes, cliente.throttles
        ),
        flush=True,
    )
    print("  Tempo ........................ {}".format(
        _formatar_duracao(time.monotonic() - inicio)), flush=True)
    print("\n  Relatório: {}".format(caminho_relatorio), flush=True)

    if suspeitas:
        print(
            "\n  ATENÇÃO: {} chave(s) marcadas como "
            "'possivel_chave_de_certificado'.\n"
            "  Elas não têm o atributo 'exportable', padrão observado nas chaves\n"
            "  geradas por certificados, mas nenhum segredo PKCS#12 correspondente\n"
            "  foi encontrado. Vale conferir antes de agir sobre elas.".format(
                suspeitas),
            flush=True,
        )

    if qtd_erros:
        print(
            "\n  {} ocorrência(s) registradas em {}".format(
                qtd_erros, caminho_erros),
            flush=True,
        )
        print("    erros: {} | avisos: {}".format(erros, avisos), flush=True)

    if interrompido or erros:
        print(
            "\n  O inventário está INCOMPLETO. Rode o script de novo para "
            "tentar apenas o que faltou.",
            flush=True,
        )

    armazenamento.fechar()
    if interrompido or erros:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(principal())
    except KeyboardInterrupt:
        _PARAR.set()
        print("\nExecução interrompida.", flush=True)
        sys.exit(130)
