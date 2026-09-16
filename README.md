# inventario_akv

Inventário das chaves criptográficas de todos os **Azure Key Vaults** em todas as
**Subscriptions** de um tenant Azure, com foco nas chaves *stand-alone* que
possuem **data de expiração**, gerando relatórios em CSV.

O script foi feito para rodar no **Python nativo do Azure Cloud Shell**, usando
apenas a biblioteca padrão do Python. A única dependência externa é o **Azure
CLI** (`az`), que já vem instalado no Cloud Shell e é usado apenas para obter o
token de acesso ao Azure Resource Manager (ARM).

Ele **não usa as APIs do próprio Key Vault** (que podem estar protegidas por
*private endpoints*). Todo o inventário é feito via **Azure Resource Manager**
(`https://management.azure.com`).

## O que ele faz

1. Lista todas as subscriptions do tenant → `subscriptions.csv`
2. Para cada subscription, lista os Key Vaults → `keyvaults.csv`
3. Para cada Key Vault, lista as chaves criptográficas → `keys.csv`
4. Para cada Key Vault, lista os segredos → `secrets.csv`
5. Gera o relatório final apenas com **chaves stand-alone expiráveis** →
   `chaves_filtradas.csv`

### Regras do filtro final

Uma chave entra no `chaves_filtradas.csv` quando:

- **possui** data de expiração; **e**
- **não** é uma chave associada a certificado — ou seja, não existe no mesmo
  cofre um segredo com `contentType = application/x-pkcs12` de mesmo nome.

## Pré-requisitos

- Azure Cloud Shell (ou um ambiente com `az` e `python3`).
- Estar autenticado no Azure (`az login` já está feito no Cloud Shell).
- Permissão de leitura (RBAC) sobre as subscriptions e Key Vaults a inventariar.

## Uso rápido (one-liner)

No Azure Cloud Shell, baixe e execute em um único comando:

```bash
curl -fsSL https://raw.githubusercontent.com/wesleyit/inventario_akv/main/run.sh | bash
```

O `run.sh` baixa a versão mais recente do `inventario_akv.py`, executa o
inventário e mantém os prompts interativos funcionando.

## Uso manual

Se preferir baixar e executar o script diretamente:

```bash
curl -fsSL https://raw.githubusercontent.com/wesleyit/inventario_akv/main/inventario_akv.py -o inventario_akv.py
python3 inventario_akv.py
```

Ou, com o repositório clonado:

```bash
git clone https://github.com/wesleyit/inventario_akv.git
cd inventario_akv
python3 inventario_akv.py
```

> Observação: evite `curl ... inventario_akv.py | python3`, pois o script faz
> perguntas interativas e precisa da entrada do terminal. Use o `run.sh` (que
> trata isso) ou baixe o arquivo antes de executar.

## Cache local

Os próprios arquivos CSV funcionam como cache. Ao iniciar, se houver CSVs de
execuções anteriores, o script informa e pergunta:

- **(C)ontinuar** — reaproveita os CSVs existentes e pula as etapas já
  concluídas;
- **(R)ecomeçar** — apaga os CSVs e refaz o inventário do zero.

Isso evita chamadas repetidas ao ARM em ambientes grandes.

## Progresso em tempo real

Durante a execução, o andamento é exibido continuamente, por exemplo:

```
Listando Key Vaults...
  Processando subscription 10 de 17: SUB_PRD_BR
    Key Vaults encontrados: 5
Listando chaves criptográficas...
  Processando Key Vault 3 de 25: kv-prod-br
    Chaves encontradas: 12
```

## Arquivos gerados

| Arquivo                | Conteúdo                                                                                           |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| `subscriptions.csv`    | `subscription_id`, `nome`                                                                          |
| `keyvaults.csv`        | `subscription_id`, `resource_group`, `nome_cofre`                                                  |
| `keys.csv`             | `subscription_id`, `resource_group`, `nome_cofre`, `nome_chave`, `data_expiracao`, `tem_expiracao` |
| `secrets.csv`          | `subscription_id`, `resource_group`, `nome_cofre`, `nome_secret`, `content_type`                   |
| `chaves_filtradas.csv` | `subscription_id`, `resource_group`, `nome_cofre`, `nome_chave`, `data_expiracao`                  |

## Licença

Veja o arquivo [LICENSE](LICENSE).
