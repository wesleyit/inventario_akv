# inventario_akv

Inventário das chaves criptográficas de todos os **Azure Key Vaults** de um
tenant Azure, gerando um CSV com as chaves que possuem **data de expiração**,
já descartando as chaves criadas automaticamente por certificados.

O script foi feito para rodar no **Python nativo do Azure Cloud Shell**, usando
apenas a biblioteca padrão do Python. A única dependência externa é o **Azure
CLI** (`az`), que já vem instalado no Cloud Shell e é usado apenas para obter o
token de acesso ao Azure Resource Manager (ARM).

Ele **não usa as APIs do próprio Key Vault** (que podem estar protegidas por
*private endpoints*). Todo o inventário é feito via **Azure Resource Manager**
(`https://management.azure.com`).

## Uso rápido (one-liner)

No Azure Cloud Shell:

```bash
curl -fsSL https://raw.githubusercontent.com/wesleyit/inventario_akv/main/run.sh | bash
```

Ao terminar, abra o `chaves_filtradas.csv` (ícone de download do Cloud Shell ou
`code chaves_filtradas.csv`).

## O relatório

`chaves_filtradas.csv`, ordenado da chave mais próxima do vencimento para a mais
distante:

| Coluna                          | Conteúdo                                                        |
| ------------------------------- | --------------------------------------------------------------- |
| `subscription_id`               | Subscription onde está o cofre                                   |
| `subscription_nome`             | Nome legível da subscription                                     |
| `resource_group`                | Resource group do cofre                                          |
| `nome_cofre`                    | Key Vault                                                        |
| `nome_chave`                    | Nome da chave                                                    |
| `data_expiracao`                | Data de vencimento (AAAA-MM-DD)                                  |
| `dias_para_expirar`             | Dias restantes; **negativo significa já vencida**                |
| `possivel_chave_de_certificado` | `sim` quando a chave merece conferência manual (veja abaixo)     |

Uma chave entra no relatório quando **possui** data de expiração e **não** é uma
chave de certificado — ou seja, não existe no mesmo cofre um segredo com
`contentType = application/x-pkcs12` e o mesmo nome.

### A coluna `possivel_chave_de_certificado`

O plano de gerenciamento do Azure não expõe nenhum campo que diga "esta chave
pertence a um certificado"; a única forma de identificá-las é o cruzamento com
os segredos PKCS#12 descrito acima. Como rede de segurança, o script observa um
segundo sinal: chaves geradas por certificados não trazem o atributo
`exportable`.

Quando os dois sinais discordam — a chave não tem `exportable`, mas nenhum
segredo PKCS#12 correspondente foi encontrado — a linha é marcada com `sim`.
**Isso não exclui a chave do relatório**, apenas sugere conferência manual. É um
comportamento não documentado pela Microsoft, então serve como alerta, nunca
como critério.

Se houver alguma ocorrência, um `erros.csv` também é gerado.

## Opções

Todas são opcionais; sem nenhuma, o script varre o tenant inteiro.

| Opção                 | Para que serve                                                      |
| --------------------- | ------------------------------------------------------------------- |
| `--dias N`            | Lista apenas chaves que vencem em até N dias                        |
| `--saida PASTA`       | Onde gravar os arquivos (padrão: pasta atual)                       |
| `--continuar`         | Retoma uma execução interrompida sem perguntar                      |
| `--recomecar`         | Descarta a execução anterior e começa do zero sem perguntar         |
| `--lotes N`           | Lotes simultâneos (padrão: 4)                                       |
| `--lotes-por-segundo` | Teto de chamadas HTTP por segundo (padrão: 4)                       |

Exemplo — o que vence nos próximos 90 dias:

```bash
python3 inventario_akv.py --dias 90
```

## Se a sessão do Cloud Shell cair

O progresso é gravado continuamente em `inventario_akv.db`. Basta reabrir o
Cloud Shell e rodar o mesmo comando: o script detecta a execução interrompida e
oferece continuar de onde parou, reprocessando apenas o que faltava — inclusive
cofres criados nesse meio-tempo.

Execuções interrompidas há mais de 12 horas são consideradas desatualizadas, e
o padrão passa a ser recomeçar do zero: em ambientes onde chaves nascem todos os
dias, um inventário que mistura épocas diferentes não é confiável.

## Como ele consegue ser rápido

Em ambientes com centenas de subscriptions e milhares de cofres, o custo não
está no processamento e sim no número de chamadas HTTP. Três decisões atacam
isso:

1. **Descoberta pelo Azure Resource Graph** — todos os cofres do tenant vêm em
   poucas consultas, em vez de uma consulta por subscription.
2. **API de batch do ARM** — as leituras viram uma fila única de URLs drenada em
   lotes de 20 por chamada HTTP, reduzindo em 20x as idas e vindas na rede.
   Cada item do lote tem seu próprio status, então a falha em um cofre não
   contamina os demais.
3. **Poda** — os segredos só são lidos nos cofres que têm alguma chave com
   expiração, já que servem apenas para identificar chaves de certificado.

O script também se autolimita: respeita `Retry-After`, reduz o ritmo ao receber
`429` e pausa as leituras de uma subscription cuja cota do ARM esteja acabando.
A intenção é nunca prejudicar outros serviços que dependem do mesmo tenant.

## Confiabilidade do inventário

Num relatório de expiração de chaves, um dado faltando em silêncio é pior que
uma falha visível. Por isso:

- Cofres que não puderam ser lidos vão para o `erros.csv` e **nunca** são
  omitidos silenciosamente.
- Se houver qualquer erro, o script termina com código de saída `2` e avisa que
  o inventário está incompleto.
- Se o Resource Graph truncar o resultado da descoberta, a execução é abortada.
- Se a sua conta não enxergar todas as subscriptions do tenant, um aviso é
  exibido — o inventário só alcança o que o RBAC permite ler.

## Pré-requisitos

- Azure Cloud Shell (ou um ambiente com `az` e `python3`).
- Estar autenticado no Azure (`az login` já está feito no Cloud Shell).
- Permissão de leitura (RBAC) sobre as subscriptions e Key Vaults a inventariar.
  Para cobrir o tenant inteiro, o ideal é `Reader` no management group raiz.

## Massa de teste (para quem mantém o script)

O `gerar_massa_teste.py` cria Key Vaults e chaves com datas de expiração
variadas, para exercitar o inventário em escala antes de rodá-lo em produção.
**Não é para o usuário final** — é ferramenta de quem desenvolve e valida.

```bash
# 20 cofres com 1000 chaves cada (o padrão)
python3 gerar_massa_teste.py --grupo rg-carga-akv

# algo menor, para uma verificação rápida
python3 gerar_massa_teste.py --grupo rg-carga-akv --cofres 5 --chaves 100

# apaga tudo o que foi criado (exclusão + purge)
python3 gerar_massa_teste.py --grupo rg-carga-akv --remover
```

| Opção            | Para que serve                                               |
| ---------------- | ------------------------------------------------------------ |
| `--grupo RG`     | Resource group de destino (criado se não existir); **obrigatório** |
| `--local`        | Região (padrão: `eastus`)                                    |
| `--cofres N`     | Quantidade de cofres (padrão: 20)                            |
| `--chaves N`     | Chaves por cofre (padrão: 1000)                              |
| `--sem-data PCT` | Percentual de chaves sem expiração (padrão: 15)              |
| `--prefixo`      | Prefixo dos nomes dos cofres (padrão: `akv-carga`)           |
| `--paralelismo`  | Criações simultâneas (padrão: 24)                            |
| `--rsa`          | Usa RSA 2048 em vez de EC P-256                              |
| `--remover`      | Exclui e faz purge dos cofres com o prefixo, e sai           |
| `--sim`          | Não pede confirmação                                         |

As datas são sorteadas entre 120 dias no passado e 3 anos à frente, então o
relatório sai com chaves já vencidas, vencendo em breve e distantes.

Alguns detalhes que importam na hora de usar:

- **Também funciona sem acesso ao data plane.** As chaves são criadas via
  `management.azure.com`, o mesmo caminho do inventário, então a ferramenta
  roda mesmo em ambientes onde os cofres estão atrás de Private Endpoint.
- **É idempotente.** Ele lista o que já existe antes de criar, então dá para
  interromper e retomar, ou aumentar `--chaves` depois para complementar os
  cofres existentes.
- **Os nomes são estáveis**, derivados da subscription e do resource group.
  Reexecuções e o `--remover` sempre acertam os mesmos cofres.
- **EC P-256 é o padrão** por ser muito mais rápido de gerar que RSA. Como o
  inventário só lê metadados, o tipo da chave é indiferente para o teste.
- **O `--remover` faz purge**, não só exclusão. Sem isso o soft-delete
  impediria recriar cofres com os mesmos nomes.

### O que ele não consegue reproduzir

O plano de gerenciamento não expõe endpoint de certificados, então a massa
gerada **não contém chaves criadas por certificados** — justamente o caso que o
inventário precisa descartar. O teste de carga exercita volume, paginação e
throttling, mas não a regra de exclusão PKCS#12; essa continua dependendo de
validação num ambiente que já tenha certificados.

## Licença

Veja o arquivo [LICENSE](LICENSE).
