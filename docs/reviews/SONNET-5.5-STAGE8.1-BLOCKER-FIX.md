# FIX MY PC — Etapa 8.1: Correção dos bloqueadores da homologação

- **Modelo responsável:** Claude Sonnet 5.5
- **Data:** 2026-11-20
- **Projeto:** FIX MY PC: Windows Diagnostic & Audit Skill (`v0.1.0`)
- **Workspace:** `<workspace>`
- **Classificação final:** **APROVADO PARA REVISÃO INDEPENDENTE**

> **Nota sobre homologação:** Este parecer registra exclusivamente correções e validações offline com fixtures sintéticas e mocks em ambiente isolado. **Nenhuma auditoria real do Windows foi executada** e nenhuma autorização de homologação real é declarada aqui; essa decisão depende de nova revisão independente.

---

## 1. Defeitos reproduzidos antes da correção

Todos os achados apontados pela revisão independente da Etapa 8 (`docs/reviews/GPT-SOL-6.2-POST-V2-INDEPENDENT-REVIEW.md`) foram reproduzidos antes das alterações:

1. **Bloqueante — FMP-08 (vazamento de LUID em `displayName`):**
   - Entrada sintética em `startup.autoServices`: `name = 'OneSyncSvc_1a2b3'`, `displayName = 'Sync Host_1a2b3'`.
   - Saída antes da correção: `{"name":"OneSyncSvc_\u003cLUID\u003e","displayName":"Sync Host_1a2b3"}`.
2. **Bloqueante — Truncamento silencioso de coleções (`151 -> 150` com `truncated = false`):**
   - Entrada sintética com `advanced.installedApps = { status: 'ok', totalCount: 151, truncated: false, items: [151 itens] }`.
   - Saída antes da correção: `totalCount=151 items=150 truncated=False`, sem sinalização em JSON ou HTML.
3. **Hardening — Prova do receptor no scanner AST:**
   - Trecho analisado apenas como texto (`Test-FmpScriptCompliance -Role collector`): `$d = @{ numbers = [int]7 }; $d.numbers.Clear()`.
   - Resultado antes da correção: `Ok=True Violations=0`.
   - Casos sintéticos adicionais (`X16`, `X17`, `X18`, `X19`, `X21`, `X22`) também falharam na fase RED (`Ok=True`).
4. **FMP-06 — Completude de `startup.high_count`:**
   - Fixture sintética com `startup.items` e `startup.logonTasks` presentes, `startup.registry`/`startup.folders`/`startup.logonTasks` em `pass` e apenas `startup.autoServices` em `access_denied`.
   - Resultado antes da correção: `State=access_denied`.
5. **Manifesto de distribuição em cópia limpa:**
   - Execução de `tools/Test-DistributionManifest.ps1` em cópia limpa sem `.playwright-mcp/`, `.commandcode/`, `.impeccable/` e `out/` falhou com `exit 1` (`FAIL [neverShip] pattern matches nothing`).
   - Também havia arquivos locais em `graphify-out/` (presentes no `.gitignore`, mas ausentes no `neverShip` do manifesto).
6. **Exceção ampla do `impeccable`:**
   - `.impeccable/config.json` continha regra ampla `side-tab=*` sobre `templates\style.css` (que, além de abrangente demais, não filtrava o caminho no Windows na CLI `impeccable detect --json templates/style.css`, retornando 2 avisos nas linhas 131 e 139 com `exit 1`).

---

## 2. Causas confirmadas

1. **FMP-08 (`src/security/Privacy.ps1`):** A regex global de LUID (`(?i)\b([a-z]*(?:svc|service))_[0-9a-f]{4,8}\b`) exigia que o prefixo terminasse em `Svc` ou `Service`, ignorando nomes de exibição reais do Windows como `Sync Host_1a2b3` e sufixos com mais de 8 dígitos hexadecimais.
2. **Truncamento silencioso (`src/security/Privacy.ps1`, `src/reports/HtmlRenderer.ps1`, `schemas/diagnostic.schema.json`):** `ConvertTo-FmpSanitizedDiagnostic` cortava qualquer `IEnumerable` em `$MaxArrayItems = 150` (e `evidence` em 80) sem registrar o corte nem atualizar o estado de coleções que possuíam `truncated` (como `advanced.installedApps`, cujo coletor usa cap de 300). O renderizador HTML também não exibia aviso de limitação aplicada pela sanitização.
3. **Prova do receptor AST (`src/security/ReadOnlyPolicy.ps1`, `src/analysis/Evidence.ps1`):** `Get-FmpReceiverProblem` continha o atalho `$script:FmpElementReceiverMethods = @('Add', 'Append', 'Clear', 'Remove', 'Sort')`, aceitando qualquer membro ou índice de uma raiz `dict`/`obj` comprovada sem comprovar o tipo efetivo do membro. Além disso, `ConvertTo-FmpSerializable` e `Hide-FmpSanitizedNode` estavam declarados em `$script:FmpDataFunctions` apenas como `'dict'`, embora possam devolver `array`, `string`, `scalar` ou `null`.
4. **Completude de inicialização (`src/analysis/Rules.ps1`):** `Test-FmpRule_startup_high_count` verificava `(Get-FmpValue $check 'id') -like 'startup.*'`, acoplando a regra a `startup.autoServices` mesmo após FMP-06 ter retirado serviços automáticos da contagem.
5. **Manifesto (`tools/Test-DistributionManifest.ps1`, `distribution-manifest.json`):** O laço de validação exigia correspondência em disco para todos os grupos, incluindo `neverShip`, e `distribution-manifest.json` ainda não listava `graphify-out/*` em `neverShip`.
6. **Impeccable (`.impeccable/config.json`, `templates/style.css`):** Supressão global por arquivo via `ignoreValues` (`side-tab=*`) em vez de supressão oficial por linha apenas nas duas declarações aprovadas.

---

## 3. Arquivos modificados

| Arquivo | Finalidade da alteração |
|---|---|
| [src/security/Privacy.ps1](../../src/security/Privacy.ps1) | Correlação de LUID por entrada de serviço (`name`/`displayName`), ampliação `{4,16}` para prefixos `Svc`/`Service`, rastreamento de coleções truncadas na sanitização (`privacy.truncated`, `privacy.truncatedCollections`, `collectionTruncated`, `sanitizedTruncated`, `presentedCount`, `truncated`). |
| [src/reports/HtmlRenderer.ps1](../../src/reports/HtmlRenderer.ps1) | Exibição de avisos localizados quando `installedApps`, `startup.*` ou `privacy.truncated` indicam corte na coleta ou na sanitização. |
| [schemas/diagnostic.schema.json](../../schemas/diagnostic.schema.json) | Inclusão dos campos opcionais `collectionTruncated`, `sanitizedTruncated`, `presentedCount`, `privacy.truncated` e `privacy.truncatedCollections`. |
| [locales/en.json](../../locales/en.json) | 5 novas chaves de aviso de truncamento (total: 422 chaves). |
| [locales/pt-BR.json](../../locales/pt-BR.json) | 5 chaves correspondentes em PT-BR (total: 422 chaves). |
| [src/security/ReadOnlyPolicy.ps1](../../src/security/ReadOnlyPolicy.ps1) | Remoção do atalho `$script:FmpElementReceiverMethods`; rastreamento de forma (`fields`/`dyn`) em `Get-FmpBindings` e `Get-FmpExprShape`; revisão dos contratos de `ConvertTo-FmpSerializable` e `Hide-FmpSanitizedNode` em `$script:FmpDataFunctions`. |
| [src/analysis/Evidence.ps1](../../src/analysis/Evidence.ps1) | Substituição de `$Ctx.<lista>.Add(...)` por `Add-FmpContextListItem` com `List[object]` local + `IDictionary.Remove`/`Add`, eliminando dependência de atalho de membro não comprovado; leitura segura via `@($ctx['...'])`. |
| [src/analysis/Rules.ps1](../../src/analysis/Rules.ps1) | Restrição da checagem de completude de `startup.high_count` às fontes contadas (`startup.registry`, `startup.folders`, `startup.logonTasks`, `startup.module`). |
| [tools/Test-DistributionManifest.ps1](../../tools/Test-DistributionManifest.ps1) | Padrões `neverShip` tornados opcionais quando ausentes no disco; grupos `runtime` e `development` continuam obrigatórios. |
| [distribution-manifest.json](../../distribution-manifest.json) | Adição de `"graphify-out/*"` ao grupo `neverShip`; bloqueios `LICENSE-PENDING` e `LEGAL-REVIEW` preservados. |
| [.impeccable/config.json](../../.impeccable/config.json) | Remoção da exceção ampla `side-tab=*`. |
| [templates/style.css](../../templates/style.css) | Supressão oficial `/* impeccable-disable-line side-tab -- ... */` restrita às linhas 131 e 139. |
| [tests/fixtures/bad-scripts/scanner-adversarial.txt](../../tests/fixtures/bad-scripts/scanner-adversarial.txt) | Atualização de `G06` e adição das regressões `G16`–`G17` e `X16`–`X22`. |
| [tests/Run.Tests.ps1](../../tests/Run.Tests.ps1) | Regressões de LUID, suíte `Q` (truncamento 0/1/149/150/151/300, coleta vs sanitização, aninhadas), completude FMP-06 (`autoServices` `access_denied`), regressão AST e E2E CLI em PT-BR e EN. |
| [docs/reviews/SONNET-5.5-STAGE8.1-BLOCKER-FIX.md](SONNET-5.5-STAGE8.1-BLOCKER-FIX.md) | Relatório final da Etapa 8.1. |

---

## 4. Correções realizadas

- **FMP-08:** Em `ConvertTo-FmpSanitizedDiagnostic`, cada entrada de serviço (`$field -eq 'autoServices'` ou objeto com `name`, `displayName` e propriedade de serviço) compara sufixos hexadecimais `_[0-9a-fA-F]{4,16}` entre `name` e `displayName` antes da sanitização individual. Quando o sufixo aparece em ambos os campos da mesma entrada (independentemente de o prefixo terminar em `Svc`/`Service`) ou acompanha `Svc`/`Service` na mesma entrada, ambos os campos têm `_<sufixo>` substituído por `_<LUID>`. A regex global para strings avulsas com sufixo `Svc`/`Service` passou a aceitar de 4 a 16 dígitos hexadecimais com fronteira `(?![\w])`.
- **Truncamento:** `Hide-FmpSanitizedNode` passa a contabilizar `$totalInNode` (e aplicar o teto de 80 para `evidence` em passagem única) registrando em `$sanitized.privacy.truncatedCollections` o caminho (`path`), `originalCount` e `retainedCount`. Em objetos que carregam `truncated` + `items`/`groups`, preserva o valor de entrada em `collectionTruncated`, registra `sanitizedTruncated` e `presentedCount`, e define `truncated = ($collectionTruncated -or $sanitizedTruncated)`.
- **AST:** `Get-FmpBindings` agora propaga mapas de campos (`fields`) e elementos dinâmicos (`dyn`) para dicionários locais e atribuições `a.b = x` / `a[k] = x`. `Get-FmpExprShape` resolve a forma do receptor efetivo em expressões de membro e índice sem aceitar membros desconhecidos ou de parâmetros `[IDictionary]` não comprovados.
- **Completude FMP-06:** `Test-FmpRule_startup_high_count` verifica apenas `startup.registry`, `startup.folders`, `startup.logonTasks` e `startup.module`, preservando a falha quando uma fonte contada está indisponível.
- **Manifesto e Impeccable:** `neverShip` opcional no verificador de manifesto; regra `side-tab=*` removida do `.impeccable/config.json` e substituída por comentários `impeccable-disable-line side-tab` apenas nas linhas 131 e 139 de `templates/style.css`.

---

## 5. Resultado LUID antes/depois

| Caso de teste | Antes | Depois |
|---|---|---|
| `OneSyncSvc_1a2b3` / `Sync Host_1a2b3` (JSON sanitizado) | `name: OneSyncSvc_<LUID>`, `displayName: Sync Host_1a2b3` | `name: OneSyncSvc_<LUID>`, `displayName: Sync Host_<LUID>` |
| `OneSyncSvc_1a2b3` / `Sync Host_1a2b3` (HTML PT-BR e EN) | Exibia `Sync Host_1a2b3` | Exibe `Sync Host_&lt;LUID&gt;`; zero ocorrências de `1a2b3` |
| Prefixo sem `Svc`/`Service` (`UserBroker_9e8d7c6b` / `User Broker_9e8d7c6b`) | Vazava em ambos os campos | Ambos mascarados (`_<LUID>`) |
| Comprimentos distintos (4 hex `f0e1`, 12 hex `a1b2c3d4e5f6`) | >8 chars não mascarados; `displayName` vazava | Mascarados em JSON e HTML |
| Sem LUID / sufixo curto / semelhantes (`Spooler`, `Svc_12`, `App_2024_x64`, `Service_v2`, `Diff_dead`/`Diff_beef`, `App_2024 and Sync Host 1a2b3`) | Preservados | Preservados integralmente |
| Conteúdo XSS (`Sync Host_1a2b3<script>alert(1)</script>`) | Vazava `1a2b3` no HTML | LUID mascarado e tag escapada (`&lt;LUID&gt;&lt;script&gt;...`) |
| JSON interno opt-in (`-IncludeInternalJson`) | Mantinha `OneSyncSvc_1a2b3` / `Sync Host_1a2b3` | Contrato preservado (mantém valores brutos) |

---

## 6. Resultado 150/151 antes/depois

| Cenário | Antes | Depois |
|---|---|---|
| 0, 1, 149, 150 itens (`truncated=false`) | Sem aviso | `truncated=false`, `collectionTruncated=false`, `sanitizedTruncated=false`, `totalCount=N`, `presentedCount=N`, `privacy.truncated=false`, sem falso aviso no HTML |
| 151 itens (`truncated=false`) | `totalCount=151`, `items=150`, `truncated=false` | `totalCount=151`, `presentedCount=150`, `items=150`, `truncated=true`, `collectionTruncated=false`, `sanitizedTruncated=true`, `privacy.truncated=true`, aviso explícito no HTML (PT-BR e EN) |
| 300 itens (`truncated=false`) | `totalCount=300`, `items=150`, `truncated=false` | `totalCount=300`, `presentedCount=150`, `truncated=true`, `collectionTruncated=false`, `sanitizedTruncated=true`, entrada em `privacy.truncatedCollections` |
| Originalmente truncada na coleta (`350 -> 300`, depois `-> 150`) | `truncated=true` sem distinguir corte da sanitização | `totalCount=350`, `presentedCount=150`, `truncated=true`, `collectionTruncated=true`, `sanitizedTruncated=true` |
| Originalmente truncada abaixo de 150 (`200 -> 120`) | `truncated=true` | `totalCount=200`, `presentedCount=120`, `truncated=true`, `collectionTruncated=true`, `sanitizedTruncated=false`, `privacy.truncated=false` |
| Coleções aninhadas (`151` e `152` itens) | Corte silencioso | `privacy.truncated=true` e `privacy.truncatedCollections` com cada caminho aninhado |

Limites mantidos: `$MaxArrayItems = 150`, `$MaxStringLength = 400`, `evidence` em `80` e teto de `8 MiB` por artefato.

---

## 7. Scanner AST e regressões

- **Removido:** atalho genérico `$script:FmpElementReceiverMethods` que aceitava `Add/Append/Clear/Remove/Sort` em qualquer propriedade de um dicionário comprovado.
- **Adicionado:** rastreamento de campos/índices em `Get-FmpBindings` + `Get-FmpExprShape` (sem alterar o comportamento de leitura segura nem reescrever o scanner).
- **Contratos revisados em `$script:FmpDataFunctions`:** `ConvertTo-FmpSerializable` e `Hide-FmpSanitizedNode` agora declaram `@('dict', 'array', 'string', 'scalar', 'null')`, impedindo chamadas mutáveis como `.Clear()` sem prova adicional.
- **Regressões executadas exclusivamente via parser/análise estática (nunca executadas):**
  - `G16` (receptor local comprovado em lista dentro de hashtable): aceito.
  - `G17` (`New-FmpCollectorContext` -> `.Clear()`): aceito.
  - `X16` (`$d = @{ numbers = [int]7 }; $d.numbers.Clear()` — reprodução exata): rejeitado (`receiver_not_proven`).
  - `X17` (`$d = @{}; $d.missing.Clear()`): rejeitado (`receiver_not_proven`).
  - `X18` (`param([IDictionary]$Ctx) $Ctx.errors.Add(1)`): rejeitado (`receiver_not_proven`).
  - `X19` (`$d = @{ file = Get-Item ... }; $d.file.Clear()`): rejeitado (`receiver_not_proven`).
  - `X20` (`$p = Get-Process; $p.Remove(0)`): rejeitado (`receiver_not_proven`).
  - `X21` (`$ctx = New-FmpCollectorContext 'x'; $ctx.unknown.Clear()`): rejeitado (`receiver_not_proven`).
  - `X22` (`$s = ConvertTo-FmpSerializable 'abc'; $s.Clear()`): rejeitado (`receiver_not_proven`).
  - Todas as operações legítimas do projeto (`Evidence.ps1`, `Events.ps1`, `Storage.ps1`, `G01`–`G15`): aceitas (`ValidateOnly` 0 violações nos 15 arquivos).

---

## 8. Completude de Inicialização

- `startup.high_count` agora ignora `startup.autoServices` na verificação de completude de `subChecks`, avaliando apenas `startup.registry`, `startup.folders`, `startup.logonTasks` e `startup.module`.
- Regressões adicionadas em `tests/Run.Tests.ps1` (Suíte M):
  - `startup.autoServices = access_denied` com itens e tarefas disponíveis -> `pass`.
  - `startup.logonTasks = access_denied` (fonte efetivamente contada indisponível) -> `access_denied`.
- Outras regras de inicialização (`startup.unsigned_autostart`) não foram modificadas.

---

## 9. Manifesto em workspace completo e cópia limpa

- **Workspace completo:** `tools/Test-DistributionManifest.ps1` — **PASS** (`exit 0`; runtime `1.222.323 B`, neverShip `5.076.997 B`, development `30.782.198 B` antes da gravação deste parecer).
- **Cópia limpa** (excluindo `.playwright-mcp`, `.commandcode`, `.impeccable`, `graphify-out`, `out`): **PASS** (`exit 0`; runtime `1.222.323 B`, neverShip `0 B`, development `30.782.198 B`).
- **Bloqueios preservados:** `LICENSE-PENDING` e `LEGAL-REVIEW` continuam registrados em `distribution-manifest.json`.
- Arquivos obrigatórios de `runtime` e `development` continuam exigidos; apenas `neverShip` permite 0 ocorrências.

---

## 10. Supressão específica do impeccable

- Removido `side-tab=*` de `.impeccable/config.json` (`ignoreValues: []`).
- Aplicado comentário oficial `/* impeccable-disable-line side-tab -- Approved top-edge risk tint (4px inset top shadow on .score-card, not a side tab) */` exclusivamente nas linhas 131 (`.score-card.risk-elevated`) e 139 (`.score-card.risk-critical`) de `templates/style.css`.
- Verificações com `impeccable detect --json` (versão instalada):
  - `templates/style.css`: `[]` (`exit 0`).
  - Cópia temporária com uma 3ª ocorrência sintética (`.fake-card { border-left: 4px solid #ff0000; }` na linha 372): detectada (`exit 2`).

---

## 11. Compatibilidade PowerShell

- **Windows PowerShell 5.1:** todas as suítes offline, `-ValidateOnly`, E2E em modo fixture e manifesto executaram e passaram com `Set-StrictMode -Version 3.0`.
- Durante a validação foi identificada e tratada uma particularidade do PS 5.1 com `OrderedDictionary` sob parâmetro `[System.Collections.IDictionary]` (ambiguidade entre `IOrderedDictionary.Item[int]` e `IDictionary.Item[object]`): `Add-FmpContextListItem` em `src/analysis/Evidence.ps1` utiliza `Get-FmpValue` para leitura e `Remove`/`Add` para atualização, e `Invoke-FmpCollector` lê os arrays por chave indexada (`$ctx['...']`).
- **PowerShell 7:** `pwsh` não está instalado neste ambiente (não foi instalado conforme restrição), permanecendo não validado diretamente nesta etapa.

---

## 12. Testes e códigos de saída

Todas as execuções ocorreram exclusivamente com mocks/fixtures em modo offline (sem `-AcceptReadOnlyPolicy` e sem consultar o sistema real):

| Verificação | Resultado | Código de saída |
|---|---|---:|
| `tests/Collector.Tests.ps1` | **85/85** | `0` |
| `tests/Visual.Tests.ps1` | **290/290** | `0` |
| `tests/Run.Tests.ps1` (inclui E2E CLI PT-BR/EN e chamadas a Collector/Visual) | **423/423** | `0` |
| `fixmypc.ps1 -ValidateOnly` | **PASS** (15 arquivos, 0 violações, 422 chaves/idioma, `rules.json` OK) | `0` |
| `tools/Test-DistributionManifest.ps1` (workspace completo) | **PASS** | `0` |
| `tools/Test-DistributionManifest.ps1` (cópia limpa sem caches locais) | **PASS** | `0` |
| CLI fixture E2E Etapa 8.1 (`pt-BR` com `-IncludeInternalJson` e `en`) | **PASS** (`report.html` 777.415 B / 773.232 B; 0 scripts, 0 `on*=`, 0 URL externa, 0 `1a2b3`) | `0` / `0` |
| Validação `schemas/diagnostic.schema.json` (`jsonschema` 4.26.0 sobre `samples/*.json` + E2E) | **PASS** (5/5 documentos válidos) | `0` |
| `impeccable detect --json templates/style.css` | `[]` (0 avisos) | `0` |
| `impeccable detect --json` (cópia com 3º `side-tab` sintético) | 1 aviso detectado na linha 372 | `2` |

---

## 13. Impactos sobre o HTML/JSON

- **JSON:**
  - `privacy.truncated` (`boolean`) e `privacy.truncatedCollections` (`[{ path, originalCount, retainedCount }]`) adicionados ao bloco `privacy` do JSON sanitizado.
  - Em objetos de coleção que possuem `truncated` + `items`/`groups` (como `advanced.installedApps`, `events.logs.*`, `advanced.signatures`), adicionados `collectionTruncated`, `sanitizedTruncated` e `presentedCount`; `truncated` passa a refletir `collectionTruncated || sanitizedTruncated`.
  - Em `startup.autoServices`, `displayName` com LUID compartilhado ou padrão de serviço passa a usar `_<LUID>` tanto no JSON sanitizado quanto no HTML.
  - O JSON interno opt-in (`-IncludeInternalJson`) mantém os dados brutos originais sem mascaramento ou corte de sanitização.
- **HTML:**
  - Quando `installedApps` é truncado na coleta e/ou na sanitização, a seção Avançada exibe o aviso localizado correspondente; quando não há truncamento (`<= 150` itens sem corte na coleta), nenhum aviso adicional é exibido.
  - Quando `privacy.truncated` é verdadeiro, a seção Privacidade (e Inicialização, se aplicável) informa as coleções limitadas e suas contagens.
  - Mantidos offline, estáticos, sem JS, sem recursos externos, com CSP inalterada e abaixo de 8 MiB (~773–777 KB na fixture completa).

---

## 14. Riscos residuais

1. **PowerShell 7:** não testado nesta execução por ausência de `pwsh` no host.
2. **Números de série em nomes de modelo de hardware e JSON interno opt-in:** permanecem conforme política já documentada nas etapas anteriores.
3. **Análise AST:** continua sendo uma defesa em profundidade estática sobre o código do projeto; efeitos colaterais de provedores CIM/WMI ou módulos externos do Windows pertencem à validação em VM controlada.
4. **Itens P3 não bloqueantes da Etapa 8** (fora do escopo desta correção focalizada): mantidos como registrados em `docs/reviews/GPT-SOL-6.2-POST-V2-INDEPENDENT-REVIEW.md`.

---

## 15. Pendências de homologação e publicação

- **Homologação controlada:** Aguardando nova revisão independente desta Etapa 8.1 e autorização explícita do proprietário/operador para execução em VM Windows dedicada e snapshotada (Windows 10/11, PowerShell 5.1 e 7, usuário padrão e administrador, `OutDir` absoluto com ACL restrita).
- **Publicação:** Permanecem abertos os bloqueadores `LICENSE-PENDING` e `LEGAL-REVIEW` em `distribution-manifest.json`, além dos itens pré-publicação já listados na revisão independente da Etapa 8.

---

**Veredito final:** **APROVADO PARA REVISÃO INDEPENDENTE**
