# FIX MY PC — Etapa 6: correções P2 e hardening final do núcleo

- **Executor:** Claude Sonnet 5.5 (`claude-sonnet-5-5`). O pedido designa a etapa como "GPT Sol 6.2"; o nome deste arquivo segue o pedido.
- **Data:** 2026-11-20
- **Base:** `docs/reviews/CLAUDE-OPUS-5.5-FINAL-AUDIT.md` e `docs/reviews/CLAUDE-OPUS-5.5-FMP01-FMP04-FIX.md`
- **Workspace:** `<workspace>`
- **Classificação:** **APROVADO COM RESSALVAS** (ver §14)

## 1. Resumo

Oito dos nove P2 abertos foram tratados com teste de regressão que falhou antes da correção: FMP-02, 03, 05, 06, 07, 08 e a revisão complementar da pontuação, mais FMP-09 como mitigação documental. FMP-10 (marca Windows nos assets) segue aberto por decisão do pedido. FMP-01 e FMP-04 foram preservados.

| Achado | Estado | Como |
|---|---|---|
| FMP-02 setters e métodos por nome | **Resolvido** | Receptor comprovado por tipo (fluxo de dados local), não por nome |
| FMP-03 caminhos e consultas | **Resolvido** | Listas fechadas de registro, logs, classes, namespaces e chaves de filtro; função de execução `Get-FmpSafeRegistryPath` |
| FMP-05 severidades invertidas | **Resolvido** | 3 regras sobem para `review_recommended`; escala documentada e testada por grupo de dedupe |
| FMP-06 `startup.high_count` | **Resolvido** | Conta só entradas do usuário; serviços ficam em `measured.services` |
| FMP-07 CPU de ~4 s | **Resolvido** | Observação informativa, penalidade 0, `windowSec`, título renomeado |
| FMP-08 SIDs e sufixos | **Resolvido** (com resíduo: série em nome de modelo) | `<SID>`, `_<LUID>`, identificadores privados em todo campo de texto |
| FMP-09 consentimento de agentes | **Mitigado por documentação** (limite técnico inalterado, por desenho) | Texto explícito, regras por execução, avaliação do token |
| Pontuação | **Feito** | `scoreAlgorithmVersion`, nota provisória honesta, falha de Inicialização fora da nota |
| FMP-10 marca Windows | **Aberto** | Etapa visual própria |

## 2. Restrições respeitadas

- **Nenhuma auditoria real do Windows.** Nenhum uso de `-AcceptReadOnlyPolicy`. Nenhuma consulta a processos, hardware, registro, serviços, drivers, SMART ou eventos do anfitrião.
- Nenhuma elevação, instalação ou reparo. Nenhum commit, push ou publicação.
- Todas as suítes rodaram numa **cópia isolada** (`robocopy /MIR` para o scratchpad, sem `out/`). A pasta `out/` do projeto continua vazia.
- `fixmypc.ps1` só foi invocado com `-Fixture` (caminho sintético, sem acesso ao sistema; `-Yes` aqui apenas escolhe os padrões e **não** concede consentimento) ou `-ValidateOnly`. Os testes negativos de CLI continuam usando o projeto-espelho com coletores `throw`.
- Os coletores só executaram dentro do harness `Collector.Tests.ps1` (runspace sem provedor de registro, com sentinelas que lançam erro nos 25 cmdlets de consulta).
- Os trechos adversariais **só passam pelo parser**; nunca são executados.
- Nada foi instalado. O `jsonschema` já estava presente. O PowerShell 7 não está instalado e não foi instalado.

**Skills usadas (uma por vez):** `superpowers:test-driven-development` (RED antes do código em cada achado, mais prova de mutação), `superpowers:systematic-debugging` na forma de reprodução e causa antes de cada correção, `security-and-hardening` como critério do modelo de ameaça, `superpowers:verification-before-completion` na validação final. As skills `security-audit` e `review-security` citadas no pedido não existem nesta instalação (mesma constatação da auditoria).

## 3. FMP-02 — scanner AST

**Causa.** A lista de métodos de instância era por nome (`Replace`, `Remove`, `Clear`, `Stop`, `Add` aceitos em qualquer tipo) e atribuições a membros só eram sinalizadas para `$global:`/`$env:`/etc. (`ReadOnlyPolicy.ps1`, antes `:224-226` e `:305`).

**Correção.** O scanner calcula, por função, o que cada variável local pode conter (união de todas as atribuições, ponto fixo). Cada fonte tem um *tipo* (`dict`, `obj`, `list`, `sb`, `stopwatch`, `string`, `scalar`, `array`, `safepath`, `null`) ou `?` ("possível objeto vivo"). `?` nunca é aceito como receptor ou raiz de setter.

| Construção | Regra | Violação |
|---|---|---|
| `a.b = x`, `a.b += x`, `a.b++` | `a` é variável de tipo `dict`/`obj` comprovado; `a.b.c = x` não é aceito (use `a['b']['c'] = x`) | `property_setter_not_allowed` |
| `[T]::P = x` | sempre recusado | `property_setter_not_allowed` |
| `a[k] = x`, `a.b[k] = x` | raiz é variável de dado comprovado | `index_setter_not_allowed` |
| `.Add .Append .Clear .Remove .Replace .Sort .Stop` | receptor de tipo compatível com o método; `Replace`/`Stop` exigem receptor direto (único efeito colateral real: `FileInfo.Replace`) | `receiver_not_proven` |

Comprovam dado local: literais `@{}`, `[ordered]@{}`, `[pscustomobject]@{}`, `New-Object List/StringBuilder`, `Stopwatch::StartNew`, cast para tipos de valor ou string, parâmetro tipado (`[hashtable]`, `[System.Collections.IDictionary]`, `[string]`…), declaração tipada (`[System.Collections.IDictionary]$x = …`) e funções internas declaradas em `$script:FmpDataFunctions`.

**Não é uma blacklist.** O que passa é o que se prova ser dado local; o que não se prova é recusado, seja qual for o nome do método ou da propriedade.

**Hashtables, listas e objetos internos continuam livres.** O projeto inteiro passa (15 arquivos + `Run.Tests.ps1`, 0 violações).

**Ajustes de código para o projeto passar** (nenhuma mudança de comportamento):
- 6 coletores: `param($ctx)` → `param([System.Collections.IDictionary]$ctx)`. `Evidence.ps1`: `[object]$Ctx` → `[System.Collections.IDictionary]$Ctx` (4 funções).
- `Events.ps1`: escritas via `$map[$key][...]` em vez do temporário `$g`; a conversão `.ToArray()` das ocorrências foi para um laço sobre `$map.Keys` antes da ordenação.
- `HealthScore.ps1`: `$categoryCoverage[$cat]['applicable']++` em vez de `$bucket.applicable++`.
- `System.ps1`: `$ctx.data['os'][...]` em vez do temporário `$osd`.
- `Run.Tests.ps1`: variáveis de teste tipadas e cadeias `a.b.c = x` reescritas como índices.

## 4. FMP-03 — caminhos e consultas

**Causa.** `LiteralPath`, `Path` e `FilterHashtable` eram aceitos com qualquer valor.

**Correção no scanner.**
- `Get-ChildItem`, `Get-Item`, `Get-ItemProperty`, `Get-Content`, `Test-Path` (parâmetro nomeado **ou posicional**): o literal precisa estar autorizado (chaves de registro em lista fechada de 16 entradas, exatamente as lidas hoje); nos coletores, variável só se vier de `Get-FmpCheckedPath` ou `Get-FmpSafeRegistryPath`. Conteúdo não confiável (valor de registro, JSON, mensagem de evento, concatenação) → `path_argument_not_proven`.
- Recusa em qualquer papel: UNC (`\\h\s`, `//h/s`), dispositivo (`\\?\`, `\\.\`), qualificado por provedor (`FileSystem::`, `Registry::`), arquivos sensíveis conhecidos (`.ssh`, `.aws`, `id_rsa`, `config\SAM`, `ntuser.dat`, `*.pfx`, `*.kdbx` …) e entrada de caminho por pipeline (`pipeline_path_input`).
- Varredura de literais em todo arquivo (exceto testes): um literal que *pareça* local (UNC, unidade, `HKxx:`, provedor) e não seja operando de `-like/-match/-eq…` é avaliado como caminho. Nos coletores, nenhuma unidade/caminho literal é aceita.
- `Get-WinEvent`: exige `-FilterHashtable` literal; chaves só `LogName, Id, Level, StartTime, EndTime` (sem `Path`); `LogName` literal ou variável de laço sobre literais, e só `System`, `Application`, `Security`.
- `Get-CimInstance`: `-ClassName` literal de uma lista de 18 classes e `-Namespace` de 3 (`root\cimv2`, `root\SecurityCenter2`, `root\wmi`), `-Filter` constante, sem argumento posicional (`query_not_allowed`).

**Correção nos pontos de coleta.** Nova função `Get-FmpSafeRegistryPath` (mesma lista, aplicada **em tempo de execução**). `Startup.ps1` valida cada chave Run/RunOnce antes de `Test-Path`/`Get-ItemProperty`; `Advanced.ps1` faz o mesmo com as chaves Uninstall e seus pais. Consultas legítimas ao registro e às pastas de inicialização não mudam (a pasta de inicialização já usava `Get-FmpCheckedPath`). Nenhum acesso real a UNC ou SMB foi feito nem testado.

## 5. FMP-05 — severidades

**Causa.** `storage.disk_space_critical` (<5%, penalidade 10) e `storage.disk_health_unhealthy` (12) eram `attention`, abaixo das regras mais leves dos seus grupos (`review_recommended`). `events.critical_recurring` (10) tinha o mesmo defeito. O renderizador ordena por severidade e depois por penalidade, então a condição pior aparecia depois.

**Correção (só `rules.json`; penalidades inalteradas).** As três regras passam a `review_recommended`. **Escala:** `info < attention < review_recommended`; num mesmo grupo de dedupe a regra de maior penalidade nunca tem severidade menor; empates saem em ordem de penalidade. Escolhi **elevar** as regras mais graves em vez de rebaixar as leves para não reduzir nenhum alerta existente. Documentado em `docs/methodology.md` e em `scoringNotes`.

## 6. FMP-06 — inicialização

**Causa.** O total somava `items + logonTasks + autoServices`; um Windows padrão tem 80–120 serviços automáticos.

**Correção.** `startup.high_count` conta só `items + logonTasks` (Run/RunOnce, pastas Inicializar, tarefas de logon). Serviços vão para `measured.services`/`measured.items`/`measured.tasks` e para o texto do achado ("não contados"). O texto agora diz "Não desative serviços só pela quantidade." Fixture de teste com 100 serviços legítimos: `pass`. 40 itens do usuário (com 100 serviços): `finding` informativo com `total = 40`.

## 7. FMP-07 — CPU

**Correção.** `perf.cpu_sustained_high`: severidade `info`, penalidade `0`. O **id foi mantido por compatibilidade** com JSON, esquema e consumidores. O título passa a "CPU elevada durante a amostragem" / "High CPU during the sampling window" e o texto descreve uma observação curta, não carga sustentada. `values` preserva `avg`, `max`, `samples` e ganha `windowSec = (amostras − 1) × intervalo` (4 s no fixture). A janela **não** foi aumentada. Efeito na categoria Desempenho: dedução máxima 8 → 4 (só `commit_pressure` penaliza).

## 8. FMP-08 — sanitização

**Causa.** Sem padrão para SIDs nem sufixos por usuário; `PrivateIdentifiers` só atuava numa lista fechada de campos.

**Correção (`Privacy.ps1`).**
- `\bS-1-(?:5-21|12-1)(?:-\d+){3,}\b` → `<SID>`. SIDs conhecidos como `S-1-5-18` permanecem legíveis.
- `(?i)\b([a-z]*(?:svc|service))_[0-9a-f]{4,8}\b` → `$1_<LUID>`. Restrito a nomes que terminam em `Svc`/`Service`; `Svc_12` e identificadores comuns com `_` não são tocados.
- Identificadores privados (computador, usuário) agora valem em **toda** string, não só em campos como `name`. Identificadores com menos de 3 caracteres continuam restritos à lista antiga para não destruir texto.

**Teste adversarial:** SID em nome de tarefa, `CDPUserSvc_4a7f3c` em nome e em `displayName`, hostname e usuário em campos novos (`futureField`, `vendorNote`, `comments`, uma seção inteira nova); JSON compartilhável e HTML em PT-BR e EN. Texto legítimo (`wuauserv`, `S-1-5-18`, `Svc_12`, `Realtek jo audio driver`) preservado.

**JSON interno** continua opt-in (`-IncludeInternalJson`) e sem sanitização, como antes: nomes de tarefas e serviços podem conter SID/LUID nele. A minimização do produto não mudou.

## 9. FMP-09 — consentimento dos agentes

`-AcceptReadOnlyPolicy` é uma declaração de quem monta a linha de comando e **não prova que um humano autorizou a coleta**. Isto agora está explícito em `SKILL.md`, nos dois adaptadores, nos dois READMEs e em `docs/readonly-policy.md`:

- consentimento **a cada execução real**, na conversa atual, com comando, modo, idioma e pasta de saída; um "sim" anterior não vale;
- nunca guardar a flag em script, alias, gancho, tarefa agendada ou regra "sempre permitir"; preferir que a pessoa rode o comando (o prompt interativo pergunta a ela) ou manter a aprovação por comando do host.

**Solução adicional avaliada e não implementada.** Um token de consentimento emitido numa execução interativa (`-IssueConsentToken`) foi descartado: um agente com shell sob o mesmo usuário lê ou cria o arquivo do token, então acrescentaria estado persistente e complexidade sem provar que um humano respondeu. Reavaliar apenas com um canal fora do alcance do agente. O fluxo atual **não foi enfraquecido** (teste: sem flag e sem resposta, não há consentimento; `-Yes` continua sem conceder).

## 10. Pontuação — revisão complementar

Preservados: `riskLevel`, `riskReasons`, categorias elegíveis, renormalização, limite crítico configurável (49) e a separação status/confiança/risco. Pesos **não** foram recalibrados.

1. **`scoreAlgorithmVersion = "2.0"`** em `healthScore` (1 = fórmula original da v0.1.0; 2.0 = FMP-01). Opcional no esquema, então JSONs anteriores continuam válidos. Calibração de regras é versionada por `rules.json:version`.
2. **100/100 provisório.** O cartão da nota substitui a legenda de escala por: "Nenhum problema encontrado nas verificações concluídas (cobertura N%). Isto não prova que o computador está saudável." (e o equivalente em EN), mantendo número, rótulo "Pontuação provisória", medidor hachurado e o aviso existente. O JSON não muda. Nota completa (`ok`) mantém a legenda original.
3. **Falha do módulo de inicialização.** Investigada: o portão `anyModuleFailed` listava `startup` entre os módulos-base, mas desde o FMP-01 a Inicialização não tem regra-base e fica "fora da nota". Resultado demonstrável: com cobertura 100% nas categorias pontuadas, `startup: failed` tornava a nota `unavailable` mesmo sem o módulo contribuir com ponto algum. **Corrigido** somente neste ponto: uma falha de módulo bloqueia a nota apenas se o módulo alimenta uma categoria com regra-base penalizável (system→os, storage, performance continuam bloqueando; teste com `storage: failed` → `unavailable`). Se a Inicialização ganhar regra-base, o bloqueio volta sozinho. Cobertura e confiança não foram alteradas. Efeito colateral a conhecer: a falha de `startup` já não rebaixa o `status`; ela segue listada na Metodologia do relatório e a categoria segue "fora da nota".

## 11. Código alterado

| Arquivo | Mudança |
|---|---|
| `src/security/ReadOnlyPolicy.ps1` | Análise de fluxo de dados, setters/receptores, listas de registro/CIM/logs, argumentos de caminho, varredura de literais, `Get-FmpSafeRegistryPath`; cache de escopo e de receptor (desempenho) |
| `src/security/Privacy.ps1` | SID, LUID, identificadores em todo campo |
| `src/analysis/Rules.ps1` | `startup.high_count` sem serviços; `windowSec` na CPU |
| `src/analysis/HealthScore.ps1` | `scoreAlgorithmVersion`; portão de módulo por categoria penalizável; escritas por índice |
| `src/analysis/Evidence.ps1` | `$Ctx` tipado |
| `src/reports/HtmlRenderer.ps1` | nota provisória no cartão; ordem de valores (`windowSec`, `services`) |
| `src/collectors/*.ps1` (6) | `$ctx` tipado; `Events` e `System` com escritas por índice; `Startup` e `Advanced` com `Get-FmpSafeRegistryPath` |
| `rules/rules.json` | 3 severidades, CPU info/0, nota de escala |
| `locales/pt-BR.json`, `locales/en.json` | CPU, high_count, `report.score.provisionalNote` (415 chaves por idioma) |
| `schemas/diagnostic.schema.json` | `scoreAlgorithmVersion` (opcional) |
| `SKILL.md`, `adapters/*`, `README*.md`, `docs/readonly-policy.md`, `docs/methodology.md`, `CHANGELOG.md` | Consentimento, scanner, escala, pontuação |
| `samples/*` | Regeneradas a partir de fixtures (demo PT/EN, JSONs, provisória e indisponível) |
| `tests/Run.Tests.ps1`, `tests/fixtures/bad-scripts/scanner-adversarial.txt` | Suítes L–P e fixture adversarial |

`fixmypc.ps1`, `Common.ps1` e os esquemas de consentimento não foram alterados.

## 12. Testes adicionados

`tests/Run.Tests.ps1` passou de 254 para **385** asserções (+131):

| Suíte | Asserções | O que prova |
|---|---:|---|
| L. FMP-02/03 | 73 | 65 casos da fixture (50 rejeitados, 15 aceitos) + runtime de `Get-FmpSafeRegistryPath` |
| M. FMP-05/06/07 | 15 | sem inversões por grupo, ordem com 3% livre, 100 serviços → `pass`, 40 itens → alerta, CPU info/0 e títulos |
| N. FMP-08 | 19 | SID/LUID/identificadores em JSON e HTML (PT e EN), campo inesperado, preservação de dados legítimos |
| O. Pontuação | 10 | versão do algoritmo, nota provisória honesta, `startup` falho vs `storage` falho |
| P. FMP-09 | 14 | texto de consentimento nos arquivos e fluxo atual intacto |

**Fixture adversarial** (`scanner-adversarial.txt`): A1–A8 da auditoria **literais**, X01–X15 (laço, resultado direto, enumeração de membro, `++`, setter estático, `+=`, índice, receptor reatribuído, `Remove/Clear/Stop/Add` em objeto vivo, elemento de hashtable, parâmetro sem tipo), P01–P15 (dispositivo, provedor, SAM, perfil, posicional, pipeline, valor de registro, concatenação, UNC em papel `core`, leitor estático), Q01–Q12 (consultas) e G01–G15 (operações legítimas).

**Regressões que falhavam antes (RED observado):** 52 falhas na primeira execução de L (A1–A8, X, P, Q e a função de execução); em M, 4 falhas de FMP-05/06 e uma exceção que interrompeu o resto da suíte, antes de implementar; 15 falhas em N contra o `Privacy.ps1` antigo.

**Prova de mutação** (só na cópia): removi o campo de versão → a suíte O aborta no primeiro teste; desativei a nota provisória → 2 falhas; restaurei o portão antigo → 1 falha. Cada teste novo de pontuação detecta a regressão que protege.

**Expectativas existentes alteradas (mudança legítima, derivação nos testes):**

| Teste | Antes | Depois | Motivo |
|---|---|---|---|
| `low-disk: severidade` | `attention` | `review_recommended` | FMP-05 |
| `spike: dedução de desempenho` | 8 | 4 | FMP-07 (CPU 0 + commit 4) |
| `spike: pontuação` | 91 | 95 | `round(100·(85−4)/85)` |
| `B2: dedução` | 61 | 57 | idem |
| `B2: nota` | 28 | 33 | `round(100·(85−57)/85)` |

Nenhuma expectativa foi relaxada para obter PASS.

## 13. Resultados antes/depois

| Verificação | Antes | Depois |
|---|---|---|
| `tests\Run.Tests.ps1` | 254/254 | **385/385** |
| `tests\Collector.Tests.ps1` | 85/85 | **85/85** |
| `tests\Visual.Tests.ps1` | 193/193 | **193/193** |
| `fixmypc.ps1 -ValidateOnly` | PASS, 15 arquivos, 414 chaves | **PASS**, 15 arquivos, 0 violações, 415 chaves por idioma |
| Esquema JSON | — | 20 JSONs sanitizados (10 fixtures × 2 modos) válidos contra `schemas/diagnostic.schema.json` (`jsonschema` 4.26) |
| Paridade PT-BR/EN | 414 | 415 chaves idênticas |
| HTML regenerado (6 amostras) | — | 0 `<script>`, 0 atributos `on*`, 0 URL externa, CSP idêntica |

**Casos da auditoria (`Adversarial.Tests.ps1`, reexecutado offline):**

| Caso | Antes | Depois |
|---|---|---|
| A1–A8 | `scanner_ok=True` ×8 | `scanner_ok=False` ×8 (`property_setter_not_allowed`, `receiver_not_proven`, `path_not_allowed`, `query_not_allowed`) |
| C1–C9 | bloqueados | bloqueados |
| B1 disco com falha | 88 (auditoria); 49 após FMP-01 | 49 |
| B2 pior caso | 39 (auditoria); 28 após FMP-01 | 33 |
| B4 SID / `CDPUserSvc_4a7f3c` / hostname / usuário | presentes | **ausentes** (JSON e HTML) |
| B4 série em nome de modelo | presente | **ainda presente** (ver §15) |
| B5 ordem com 3% livre | `<10%` antes de `<5%` | `<5%` (10) antes de `<10%` (6), ambos `review_recommended` |
| B6 90 serviços | `finding` | `pass` |
| B7 pico de CPU | `attention`, pen 4, nota 96/95 | `info`, pen 0, nota 100 |
| B8 inglês no PT-BR | 0 | 0 |

**Notas dos fixtures (JSON sanitizado):** demo 79, win11-healthy 100, low-disk 49 (limitada), cpu-ram-spike 91 → **95**, events-mixed 81, win10-outdated 90 (provisória), limited-access 100 (provisória, cobertura 86,7%), degenerate indisponível.

**Custo do scanner.** A primeira versão custou ~19 s por execução (`-ValidateOnly`), inaceitável porque cada auditoria real paga esse tempo antes de coletar. Com cache de cadeias de escopo e de receptores, o tempo caiu para o valor registrado em §13.1 sem alterar nenhum resultado.

### 13.1 Tempos finais

Medidos na cópia isolada, Windows PowerShell 5.1, após a otimização:

| Execução | Tempo |
|---|---:|
| `fixmypc.ps1 -ValidateOnly` (leitura e análise dos 15 arquivos) | 8,2 s (era 18,9 s antes do cache) |
| `tests\Collector.Tests.ps1` | 8 s |
| `tests\Visual.Tests.ps1` | 26 s |

Não há medida do `-ValidateOnly` anterior a esta etapa (o código antigo não foi preservado), portanto o custo líquido acrescentado pelo scanner novo não está quantificado; ele existe e é pago em toda auditoria real antes da coleta. Os 8,2 s incluem a inicialização do PowerShell e a análise das regras de FMP-01 a FMP-04 já existentes. A suíte `Run.Tests.ps1` completa (385 asserções, várias execuções do CLI) levou de 2 a 5 minutos nas execuções desta etapa, contra 68 s registrados na auditoria, pela soma do scanner novo e de 131 asserções a mais; a variação entre execuções indica também carga da máquina.

## 14. Efeitos sobre JSON, HTML e pontuação

- **JSON:** `healthScore.scoreAlgorithmVersion` (novo, opcional); `findings[perf.cpu_sustained_high].values.windowSec` (novo); `checks[startup.high_count].measured = {items, tasks, services}` e `values.services` no achado; `severity`/`penalty` de 4 regras mudam; textos de CPU e `high_count` mudam; SIDs, LUIDs e identificadores privados aparecem como `<SID>`, `_<LUID>`, `<Identifier>`. Nenhum campo foi removido ou renomeado. O id `perf.cpu_sustained_high` foi mantido.
- **HTML:** título/detalhe de CPU; texto de `high_count`; severidade das 3 regras; cartão da nota provisória; nenhum novo elemento, classe CSS ou ativo. CSP inalterada.
- **Pontuação:** a fórmula não mudou. Mudam as notas por calibração de regra (CPU 4 → 0) e, em caso extremo, a disponibilidade quando só `startup` falha. `docs/methodology.md` tem a nova tabela, o pior caso (33) e o texto da dedução máxima por categoria (Desempenho 4/20).

## 15. Falhas residuais e limites

**Do scanner (FMP-02/03):** é uma aproximação conservadora, **não uma prova**.
- Não segue valores passados a funções internas, nem objetos vivos guardados dentro de um contêiner e lidos de volta. Mitigação parcial: a raiz precisa ser dado comprovado e o receptor de `Add/Append/Clear/Remove/Sort` em elemento de dicionário só vale para essas cinco operações.
- Funções internas que devolvem dados puros precisam ser declaradas à mão em `$script:FmpDataFunctions` (14 hoje). Declaração errada enfraquece a prova.
- A lista de registro é exata; qualquer nova leitura de registro exige editar `$script:FmpAllowedRegistryPaths` (intencional).
- A varredura de literais só reconhece cadeias que começam como UNC, unidade, `HKxx:` ou provedor; caminho relativo sensível em papel não coletor não é pego. Em papéis não coletores uma variável de caminho é aceita sem prova de origem (validada em tempo de execução por `Get-FmpCheckedPath`/`Get-FmpLocalPath`).
- O padrão de arquivos sensíveis é uma lista (camada extra, não a barreira principal; a barreira é a lista fechada de fontes).
- Efeitos indiretos de provedores WMI/CIM, do Defender e do autoload de módulos continuam fora do que um scanner estático prova (riscos residuais da auditoria §5.2 e §18).

**De privacidade:** números de série embutidos em nomes de modelo (`Samsung SSD … S7DNNJ0W123456X`, `WD-WCC…`) **não** são removidos; uma regex genérica destruiria nomes de modelo legítimos. O JSON interno mantém nomes brutos de tarefas e serviços.

**De consentimento:** continua declaratório por desenho (FMP-09); a proteção real é o procedimento e a aprovação por comando do host.

**De desempenho:** o scanner agora gasta mais tempo por execução que antes desta etapa (ver §13.1).

**De validação:** PowerShell 7 não validado (ausente). Nenhuma verificação em navegador (320–1440 px, impressão, contraste alto, leitor de tela) da nova frase do cartão provisório. Coletores não homologados em Windows real.

## 16. P2 e P3 ainda abertos

- **P2:** FMP-10 (identidade visual do Windows em banner e ícone; etapa visual própria). FMP-09 permanece como limitação de desenho documentada.
- **P3 não tratados (15):** arredondamento bancário, `.gitignore`/pacote e `OutDir` fora da pasta da skill, testes escrevendo em `out\`, contagens de asserções agregadas, deriva de `signatures` nas fixtures, corte de 150 itens sem `truncated`, ordenação de `Win32_ReliabilityRecords`, data de fim de suporte do 25H2, limiar de `os.outdated_patch`, falhas auxiliares engolidas, artefato parcial, harness com leituras .NET, rodapé de impressão em inglês e `forced-colors`, códigos 22/45 em `devices.problem_codes`, substituição em cascata de placeholders.
- **Decisão de licença:** pendente do proprietário.

## 17. Recomendações para Sonnet 5.5 (próxima etapa)

1. **FMP-10:** substituir banner e ícone por arte genérica de monitor, acrescentar a declaração de não afiliação e atualizar `assets/optimized` (`tools/Optimize-Assets.ps1`) e `manifest.json`; sem redesenhar o relatório.
2. **Verificação visual real da frase do cartão provisório** e dos novos textos (PT/EN), em 320, 375, 768, 1024 e 1440 px e em impressão A4. Reutilizar o fluxo de capturas de `docs/screenshots`.
3. **P3 de baixo risco e alto valor:** `.gitignore` + manifesto de pacote, `OutDir` padrão fora da pasta da skill, testes escrevendo em `%TEMP%`, arredondamento `AwayFromZero`, `forced-colors`, filtro dos códigos 22/45.
4. **Série em nome de modelo:** avaliar com amostras reais de homologação antes de qualquer regex (risco de destruir nomes legítimos).
5. **Manter `$script:FmpDataFunctions` e as listas de fontes sob revisão obrigatória** (CODEOWNERS ou item de checklist de release): são a base de confiança do scanner.
6. **Medir o custo do scanner** em Windows real e em PowerShell 7; reduzir passes de `FindAll` se necessário.

## 18. Requisitos pendentes para homologação real

Sem alteração do §19 da auditoria (matriz Windows 10/11, padrão × administrador, PS 5.1 × 7.4+, WOW64, prova de somente leitura com snapshot e ProcMon, consentimento, estados reais, privacidade, desempenho, laudo em navegadores), mais:

1. Confirmar, na máquina real, que **todas** as chaves de registro lidas hoje estão em `$script:FmpAllowedRegistryPaths` (inclusive visão WOW6432Node e HKCU) e que nenhuma lança `registry_path_not_allowed`.
2. Procurar SIDs, LUIDs, hostname e usuário reais no JSON e no HTML sanitizados (inclusive séries em nomes de modelo).
3. Registrar a contagem real de serviços automáticos e de entradas de inicialização, e confirmar que `startup.high_count` não dispara em máquina normal.
4. Registrar a janela real da amostra de CPU (`windowSec`) e confirmar a leitura "observação" no laudo.
5. Confirmar o tempo total do scanner e da coleta em máquina real.
6. Validar PowerShell 7.4+ (nenhum código desta etapa usa sintaxe exclusiva do PS7, mas não foi executado nele).

## 19. Veredito

### **APROVADO COM RESSALVAS**

**Justificativa.** Nenhum P0 e nenhum P1 abertos. Todos os P2 técnicos do escopo (FMP-02, 03, 05, 06, 07, 08) foram corrigidos com regressão que falhou antes, a revisão de pontuação foi concluída e FMP-09 foi tratado onde um desenho técnico honesto permite. A coleta continua somente leitura, local, sem rede e com consentimento por execução.

**Ressalvas:**
1. FMP-10 (marca Windows) aberto; bloqueia distribuição pública, não a homologação controlada.
2. O scanner é uma defesa em profundidade com limites documentados (§15), não uma prova de ausência de efeitos colaterais.
3. Série em nome de modelo e JSON interno continuam com dados que a sanitização não cobre.
4. PowerShell 7, navegador/acessibilidade e Windows real **não** validados.
5. Licença pendente do proprietário.

**Esta classificação não aprova distribuição pública.** Ela libera a próxima etapa (visual, FMP-10) e a homologação controlada descrita em §18.
