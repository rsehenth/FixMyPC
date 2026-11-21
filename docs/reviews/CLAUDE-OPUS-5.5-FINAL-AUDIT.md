# FIX MY PC — Etapa 5: Auditoria final independente

- **Auditor:** Claude Opus 5.5 (`claude-opus-5-5`)
- **Data:** 2026-11-20
- **Projeto:** FIX MY PC: Windows Diagnostic & Audit Skill v0.1.0
- **Workspace:** `<workspace>`
- **Natureza:** auditoria de código e artefatos. Nenhuma auditoria real do Windows foi executada. Nenhum arquivo de produção foi alterado.

---

## 1. Resumo executivo

O núcleo de segurança está sólido. A coleta só é carregada depois do consentimento (`fixmypc.ps1:164-168` antes de `:218`). `-Yes` sozinho não autoriza coleta real. Uma fixture inválida ou vazia nunca cai para a auditoria real. Todos os coletores usam somente consultas de leitura. O HTML não tem JavaScript nem referências externas. Os payloads de XSS testados saíram escapados. As escritas usam `CreateNew` dentro de um diretório único autorizado.

Todos os números informados pelas etapas anteriores foram reproduzidos: 194/194, 85/85, 193/193, 15 arquivos aprovados pelo scanner e `-ValidateOnly` PASS. Esses números, porém, não detectam os problemas abaixo.

**Achados abertos:** 0 × P0, **1 × P1**, 9 × P2, 15 × P3.

- **P1 (FMP-01) — a pontuação é estruturalmente enganosa.** A categoria Inicialização (peso 15) não tem nenhuma regra na métrica-base, então esses 15 pontos nunca podem ser deduzidos. Os tetos documentados também não são alcançáveis: Armazenamento chega a no máximo 22/30, Desempenho a 8/20 e SO a 6/10. Reproduzido: um disco que o Windows reporta como `Unhealthy`, com SMART prevendo falha e erros de disco recentes, recebe **88/100, status `ok` e confiança `high`**. O piso teórico da nota é **39**.
- **P2 relevantes:**
  - O scanner AST aceita setters de propriedade em objetos do sistema e caminhos UNC.
  - O laudo PT-BR contém texto em inglês: limitações das regras, dos coletores e da pontuação.
  - Os rótulos de severidade estão invertidos: a condição pior recebe o nível menor e aparece depois.
  - `startup.high_count` dispara em praticamente qualquer Windows real.
  - A "CPU sustentada" é medida numa janela de cerca de 4 s.
  - A sanitização deixa passar SIDs e sufixos de serviços por usuário.
  - O consentimento dos adaptadores é apenas declaratório.
  - Banner e ícone usam a identidade visual do Windows.

**Veredito: APROVADO COM RESSALVAS** (ver §20). Nenhum achado compromete o uso seguro: a coleta continua somente leitura, com consentimento e sem rede. O P1 afeta a interpretação da nota, não a segurança do host. A homologação controlada dos coletores pode prosseguir **sem usar a nota como critério de aceite**. A distribuição pública exige corrigir o P1 e a tradução, tomar a decisão de licença e marca e concluir a homologação real.

---

## 2. Escopo e limitações

**Em escopo:** todo o código PowerShell (`fixmypc.ps1`, `src/**`, `tools/**`, `tests/**`), `rules/rules.json`, `locales/*.json`, `schemas/`, `templates/style.css`, assets e manifest, amostras HTML/JSON, `SKILL.md`, adaptadores, READMEs, `docs/` e `LICENSE`.

**Limitações (o que NÃO foi verificado):**

| Item | Situação |
|---|---|
| Execução real dos coletores em Windows 10/11 | **Não executada** (proibida). Coletores revisados só por leitura e pelo harness offline. |
| PowerShell 7 | **Não instalado** no host (`pwsh: not found`). Não foi instalado. Compatibilidade PS7 **não validada**. |
| Navegador local (responsividade 320–1440, impressão A4, console, CSP) | **Não executado.** A instância Playwright local estava bloqueada por outro processo (`Browser is already in use … mcp-chrome-84827cb`). Não forcei o encerramento. O navegador embutido do app não abre `file://`. A análise visual foi **estática** (CSS e HTML). |
| Leitores de tela, axe, alto contraste, outros navegadores | **Não realizados.** |
| Exibição real de SMART, Defender, eventos e drivers | Não observada. Somente contratos e fixtures. |
| Datas do ciclo de vida da Microsoft | Não verificadas online (só consistência de calendário, ver FMP-P3-09). |

---

## 3. Metodologia

1. Leitura integral dos fluxos críticos, de ponta a ponta: CLI → scanner → consentimento → coletores → regras → nota → sanitização → renderização → escrita.
2. Análise estática do scanner AST, com **17 snippets adversariais** que só foram analisados pelo parser e nunca executados.
3. **10 cenários sintéticos de pipeline** executados em processo com os módulos não-coletores (`Common`, `ReadOnlyPolicy`, `Privacy`, `Evidence`, `Rules`, `HealthScore`, `HtmlRenderer`). `src\collectors` nunca foi carregado.
4. As suítes oficiais rodaram numa **cópia do projeto no scratchpad**. Assim, as pastas `out\fmp-tests-*` que elas criam não poluíram o workspace.
5. Cálculo de contraste WCAG sobre os tokens CSS.
6. Análise dos logs de console preexistentes em `.playwright-mcp/`, para o tema CSP.
7. Inspeção visual dos assets otimizados (banner e ícone).

Habilidades de auditoria usadas: `security-and-hardening` (modelo de ameaça e checklist). As skills `security-audit`/`review-security` citadas no pedido não existem nesta instalação. O equivalente foi feito manualmente.

---

## 4. Arquivos inspecionados

| Arquivo | Tamanho | Profundidade |
|---|---:|---|
| `fixmypc.ps1` | 16.8 KB | integral |
| `src/security/ReadOnlyPolicy.ps1` | 22.4 KB | integral |
| `src/common/Common.ps1` | 20.0 KB | integral |
| `src/security/Privacy.ps1` | 6.6 KB | integral |
| `src/analysis/Evidence.ps1`, `Rules.ps1`, `HealthScore.ps1` | 7.1/34.8/7.7 KB | integral |
| `src/reports/HtmlRenderer.ps1` | 75.9 KB | linhas 1–545, 991–1277 integral; restante por busca dirigida |
| `src/collectors/Advanced.ps1`, `Events.ps1`, `Startup.ps1`, `Storage.ps1`, `Performance.ps1` | — | integral (Performance até a linha 200) |
| `src/collectors/System.ps1` | 12.1 KB | busca dirigida (campos coletados) |
| `rules/rules.json`, `locales/*.json` | — | integral (via script) |
| `templates/style.css` | 23.2 KB | regras de layout, mídia e impressão |
| `tests/Run.Tests.ps1`, `Collector.Tests.ps1`, `Visual.Tests.ps1` | — | isolamento, contagem e chamadas de processo |
| `tools/Optimize-Assets.ps1`, `tools/Render-Samples.ps1` | — | chamadas e escritas |
| `SKILL.md`, `adapters/*`, `README*.md`, `docs/methodology.md`, `LICENSE` | — | integral ou dirigida |
| `samples/**/*.html` (6 arquivos) | 675–700 KB | varredura automática (script, on*, URLs, CSP) |
| `.playwright-mcp/*.log`, `.impeccable/`, `.commandcode/` | — | integral |

---

## 5. Segurança e política somente leitura (P0)

### 5.1 O que está correto (verificado)

- **Gate antes de tudo.** `fixmypc.ps1:58` escaneia 15 arquivos antes de qualquer dot-source de módulos. `ReadOnlyPolicy.ps1` é a base de confiança do bootstrap (documentado em `:57`).
- **Default-deny real.**
  - Comando fora da allowlist → `command_not_allowed` (`ReadOnlyPolicy.ps1:272-274`).
  - Parâmetro fora da lista → `parameter_not_allowed` (`:280-283`).
  - `&`/`.` dinâmicos → `dynamic_invocation` (`:243-245`).
  - Membro estático fora da lista → `member_not_allowed` (`:299-309`).
  - Splatting proibido (`:277`).
- Os testes adversariais confirmaram o bloqueio de:
  - `Remove-Item`;
  - `& $a`;
  - `. .\evil.ps1`;
  - `[IO.File]::Delete`;
  - `$x.Delete()`;
  - `OpenSubKey(…,$true)`;
  - `InvokeScript`;
  - `-ComputerName`;
  - `[type]'System.IO.File'`.
- **Comandos nativos** (`cmd`, `reg`, `wmic`, `powercfg` etc.) não estão na allowlist e também são barrados por texto (`:143`).
- **Rede:** nenhuma API de rede no código. Pastas Startup redirecionadas para UNC são puladas (`Startup.ps1:108-112`). Unidades de rede são rejeitadas por `Get-FmpLocalPath` (`Common.ps1:264-267`). A consulta COM ao Windows Update foi deliberadamente omitida (`Advanced.ps1:182-190`). Authenticode não é executado (`Advanced.ps1:282-287`).
- **Win32_Product** é proibido. `GetFolderPath` usa `DoNotVerify`, que não cria pastas (`Startup.ps1:12`).
- **Inventário dos coletores (somente leitura):**
  - `Get-CimInstance`: `Win32_OperatingSystem`, `Processor`, `VideoController`, `DiskDrive`, `LogicalDisk`, `DiskDriveToDiskPartition`, `LogicalDiskToPartition`, `PnPEntity`, `PnPSignedDriver`, `Service`, `PageFileUsage`, `PerfFormattedData_*`, `ReliabilityRecords`, `ReliabilityStabilityMetrics`, `root\SecurityCenter2\AntiVirusProduct`, `root\wmi\MSStorageDriver_FailurePredictStatus`.
  - Cmdlets: `Get-WinEvent`, `Get-Process`, `Get-Volume`, `Get-PhysicalDisk`, `Get-ScheduledTask`, `Get-ItemProperty`/`Test-Path` em HKLM/HKCU, `Get-ChildItem` nas pastas Startup, `Get-MpComputerStatus`, `Get-HotFix`, `Start-Sleep`.
- **Ferramentas de assets:** `tools/Optimize-Assets.ps1` (System.Drawing, `WriteAllText`) e `tools/Render-Samples.ps1` (somente fixtures) **não são referenciados** por `fixmypc.ps1` nem por `src/**`. Também não estão em `$script:FmpSourceFiles` (`ReadOnlyPolicy.ps1:62-69`). Não executam durante a auditoria.

### 5.2 Dependências de terceiros (a allowlist não prova ausência de efeitos colaterais)

O scanner prova o que o **código do projeto** chama, não o que os provedores fazem. Pontos que dependem de comportamento externo:

- **Provedores WMI/CIM:** `Win32_PnPSignedDriver`, `Win32_Reliability*` (RAC) e `MSFT_*` do Storage Management (provedores SMP de fabricantes).
- **Defender:** módulo CDXML do `Get-MpComputerStatus`.
- **Autoload de módulos:** `Storage`, `ScheduledTasks` e `Defender` são carregados via `PSModulePath`, que inclui o diretório de módulos do usuário.
- **Precedência de comandos:** alias > função > cmdlet. Sem `-NoProfile`, um perfil pode redefinir `Get-CimInstance`. Os adaptadores usam `-NoProfile` (`adapters/claude/README.md:24`).

Nenhum desses pontos é explorável por terceiros sem execução local prévia como o mesmo usuário. Ficam como **risco residual documentado** (§18).

### 5.3 Lacunas do scanner (FMP-02, FMP-03)

Ver §14. Resumo: atribuições a **propriedades** de objetos do sistema e métodos de instância permitidos **por nome** (`Replace`) passam pelo scanner. Valores de caminho também não são restringidos (UNC, segredos). O código atual **não** usa nenhum desses padrões. O impacto é a promessa "anything not explicitly allowed is a violation" (`ReadOnlyPolicy.ps1:7-8`) ser mais forte do que a implementação.

---

## 6. Consentimento (P0)

| Vetor | Resultado | Evidência |
|---|---|---|
| Coletores carregados antes do consentimento | **Não.** Dot-source em `fixmypc.ps1:218-223`, depois do gate em `:164-168`. | leitura de código |
| Consulta ao sistema antes da política | **Não.** Antes do consentimento: só leitura dos fontes, locales e argumentos do processo (`:110`). Validação de `OutDir` (`Get-Item` em componentes) só em `:171`, depois do consentimento. | leitura |
| `-Yes` como consentimento | **Não.** `$Yes` força `interactive=false` (`:114`). `Test-FmpCollectionConsent` só aceita `-AcceptReadOnlyPolicy` ou resposta interativa (`Common.ps1:209-212`). | `Run.Tests.ps1:571-572` (exit 3) |
| Fallback de fixture inválida para auditoria real | **Não.** `$synthetic = ContainsKey('Fixture')` (`:107`). Fixture vazia → exit 3 (`:108`). Fixture inválida → exit 3 (`:193-196`). | `Run.Tests.ps1:575-578` |
| Reaproveitar consentimento | **Não.** Não há estado persistente. Cada processo exige a flag. | leitura |
| Parâmetros malformados | `ValidateSet` em `Mode`/`Language` → erro de binding (exit 1) antes de qualquer código. | `Run.Tests.ps1:582-586` |
| Respostas ambíguas (`yesterday`, `10`) | Rejeitadas (regex ancorada). | `Run.Tests.ps1:588` |
| Coleta não autorizada via adaptadores | **Possível apenas no nível de prompt** → FMP-09 (P2). A flag não distingue humano de agente. | `adapters/*/…:24/13` |

Os testes negativos oficiais rodam contra um **projeto-espelho com coletores substituídos por `throw 'SYNTHETIC_COLLECTOR_REACHED'`** (`Run.Tests.ps1:544-558`). Confirmei que nenhum teste negativo pode alcançar coletores reais. Não criei testes negativos adicionais do CLI, porque os existentes cobrem os vetores pedidos e um teste novo sem espelho arriscaria a coleta real.

---

## 7. Privacidade e artefatos (P0)

**Correto:**

- O HTML é renderizado **somente** a partir do documento sanitizado. Há uma verificação explícita em `HtmlRenderer.ps1:1115-1117`.
- O JSON interno só é escrito com `-IncludeInternalJson` (`fixmypc.ps1:288,299`).
- Mensagens de eventos, linhas de comando, argumentos, caminhos, contas, serial e product key não são coletados ou são redigidos por campo (`Privacy.ps1:37-52,108-110`).
- O System não coleta nome de computador, serial ou UUID.
- Caminhos aceitos para escrita e para fixtures:
  - Rejeitados: UNC, `\\?\`, ADS (`:`), componentes terminados em `.`/espaço (o que inclui `..`) e nomes de dispositivo (`Common.ps1:258-262`).
  - Exigidos: unidade Fixed ou Removable (`:264-267`) e ausência de reparse point em cada componente existente (`:271-286`).
- A escrita usa `FileMode.CreateNew` + `FileShare.None` (`Common.ps1:322`). Arquivos existentes nunca são sobrescritos (`Run.Tests.ps1:594-596`).
- Limite de 8 MiB por artefato. Limite de profundidade e de itens na serialização.

**Riscos e defeitos:**

- **FMP-08 (P2):** SIDs (`S-1-5-21-…`), sufixos de serviços por usuário (`CDPUserSvc_xxxx`) e seriais embutidos em nomes de modelo sobrevivem à sanitização. Os identificadores privados (`COMPUTERNAME`, `USERNAME`) só são aplicados a uma lista fechada de campos (`Privacy.ps1:132-134`). Reproduzido em B4.
- **TOCTOU (residual):** `Get-FmpCheckedPath` verifica componentes e depois `File::Open` abre por caminho (`Common.ps1:271-286` vs `:322`). Um processo do mesmo usuário poderia trocar um diretório intermediário por junction entre a verificação e o uso. `CreateNew` impede sobrescrita, mas não impede escrita num alvo redirecionado. Exige atacante local com o mesmo privilégio, por isso fica como risco residual. **Não afirmo confinamento absoluto.**
- **ACLs herdadas:** `CreateDirectory` herda a ACL do pai. O `OutDir` padrão é `<raiz-da-skill>\out\…` (`fixmypc.ps1:151`). Instalada em `<projeto>\.claude\skills\fixmypc\`, a saída cai dentro do repositório do usuário, e o projeto não traz `.gitignore` → FMP-P3-03.
- **Falha parcial:** a sequência sanitizado → interno → HTML (`fixmypc.ps1:298-300`) pode deixar um subconjunto de artefatos se uma escrita posterior falhar. Os artefatos parciais estão no diretório autorizado e não contêm mais dados que o conjunto completo. P3 (FMP-P3-12).
- **Limites de array divergentes:** a sanitização corta arrays em 150 itens (`Privacy.ps1:100,124`), mas o coletor de apps corta em 300 e calcula `truncated` sobre 300 (`Advanced.ps1:248,275`). O JSON sanitizado pode ter 150 itens com `truncated=false`. P3 (FMP-P3-07).

---

## 8. Regras diagnósticas (P0/P1)

Contratos verificados nas 22 regras (`Rules.ps1`):

| Exigência | Situação |
|---|---|
| Ausência de SMART ≠ saúde | **OK.** `status` diferente de `ok` (incluindo `empty`) → `unknown`/`access_denied`/`unsupported` (`Rules.ps1:166-174`, `Storage.ps1:220`). |
| Processo desconhecido ≠ ameaça | **OK.** Não existe regra de reputação. `startup.unsigned_autostart` é informativa, com limitação explícita. |
| Evento histórico ≠ falha atual | **OK.** Recorrência só em ≤48 h por ocorrência com timestamp (`Rules.ps1:74-95`). WHEA e BSOD com limitação "historical". |
| Erro de leitura ≠ resultado positivo | **OK.** `Get-FmpRuleNumber` rejeita string, bool e não-finitos (`:34-41`). Logs `access_denied`/`error` propagam o estado (`:59-72`). |
| Driver antigo ≠ defeituoso | **OK.** A idade do driver não é avaliada. |
| AV registrado ≠ proteção ativa | **OK.** `defender_disabled` vira `unknown` se há AV de terceiros (`:502-504`). O texto diz "Registrado no Centro de Segurança". |
| Sem updates conhecidos ≠ atualizado | **Parcial.** Existe a limitação `hotfixes_cbs_only`, mas `os.outdated_patch` dá `pass` sempre que o hotfix mais recente tem ≤365 dias. Isso é frouxo (11 meses sem patch = pass). Como a regra é só de análise, fica em P3 (FMP-P3-10). |
| CPU alta por segundos ≠ defeito permanente | **Falha parcial → FMP-07 (P2).** |
| Timestamps e timezones | **OK.** Serialização em UTC (`Common.ps1:162-163`). `Get-FmpHoursBetween` converte ambos para UTC. O HTML rotula "UTC". |
| Deduplicação | **OK.** `RecordId` nos eventos (`Events.ps1:53-58`). Grupos de dedupe na nota. Kernel-Power 41 e EventLog 6008 combinados por `Max` (`Rules.ps1:270-271`). |
| Truncamento | **OK.** Log truncado → `unknown` quando não há achado (`Rules.ps1:67`) e aviso no HTML. |
| Estados inconclusivos | **OK.** Os 7 estados são preservados e um estado fora do conjunto vira `error` (`Rules.ps1:596`). |

**Falsos positivos e negativos encontrados:**

- **FMP-05 (P2):** a severidade das regras de armazenamento está invertida em relação à escala documentada.
- **FMP-06 (P2):** `startup.high_count` soma **todos** os serviços automáticos. Um Windows padrão tem 80–120 → o achado dispara em qualquer máquina (B6).
- **FMP-07 (P2):** CPU "sustentada" com 3 amostras em ~4 s, severidade `attention` e penalidade 4 (B7).
- **P3:**
  - `devices.problem_codes` conta o código 22 (desativado pelo usuário) e o 45 (não conectado) como problema.
  - `os.outdated_patch` frouxo.
  - `startup.unsigned_autostart` nunca é avaliável em execuções reais, porque o coletor sempre grava `not_collected` (`Advanced.ps1:283-286`). As fixtures, ao contrário, trazem `status: ok`, o que é deriva de contrato.

---

## 9. Pontuação

**Matemática (correta como implementada):** começa em 100. Deduz apenas `finding` com penalidade > 0 de regras-base (`HealthScore.ps1:77-90`). O dedupe pega a maior penalidade do grupo (`:87`). O teto é por categoria (`:93`). Os pesos são validados (soma 100 e finitos, `:26-34`). Nulos não penalizam. Estados não-`pass`/`finding` não contam como cobertura. A nota fica `unavailable` (`score=null`) abaixo de 35% de cobertura ou se `system`/`storage`/`performance`/`startup` falhar (`:139-145`). Fica `provisional` com qualquer verificação inconclusiva. O renderizador não reinterpreta a nota: usa `score`, `status` e `categories` do JSON e não desenha barra para categoria sem evidência (`HtmlRenderer.ps1:515-525`). **Isso atende** ao requisito "categorias sem evidência não aparecem como saudáveis" **no nível da barra**.

**Problema de modelo (FMP-01, P1).** Dedução máxima alcançável por categoria, calculada das regras em `rules.json` e confirmada em B2:

| Categoria | Peso | Regras-base que penalizam (após dedupe) | Dedução máx. | Alcançável |
|---|---:|---|---:|---:|
| Armazenamento | 30 | espaço (10) + saúde (12) | 22 | 73% |
| Eventos | 25 | recorrência (10) + WHEA (8) + estabilidade (8) = 26 → teto | 25 | 100% |
| Desempenho | 20 | CPU (4) + commit (4); RAM é informativa (0) | 8 | 40% |
| Inicialização | 15 | **nenhuma regra-base** (`rules.json:185-197`: `modes: ["full"]`, penalidade 0) | **0** | **0%** |
| SO | 10 | EOL (6); uptime é informativo | 6 | 60% |
| **Total** | 100 | | **61** | **piso = 39** |

Consequências observadas:

- **B0:** máquina saudável → `startup: 0/0 rem=15`, com status `ok` e confiança `high`. Os 15 pontos de Inicialização entram na nota sem nenhuma verificação.
- **B1:** disco `Unhealthy` + SMART `predictFailure` + 12 erros `disk` em 48 h → **88, `ok`, confiança `high`**.
- **B2:** todas as regras-base em falha → **39, `ok`**.

A documentação promete pesos que a implementação não entrega: `README.md:36`, `README.pt-BR.md:32` e `docs/methodology.md:42` ("Inicialização 15"). A comparabilidade entre modos é preservada (as regras só da Completa não penalizam), mas isso também é o que deixa Inicialização sem efeito.

**P3:** `[Math]::Round` usa arredondamento bancário (`HealthScore.ps1:114`): 87,5 → 88 e 86,5 → 86. A barra de uma categoria **parcialmente** coberta (ex.: 1/5) aparece cheia se não houver dedução (`HtmlRenderer.ps1:515-519`). Isso é mitigado pelo rótulo "(1/5 cobertas)" e pelo status `provisional`.

---

## 10. HTML, assets e CSP

**Comprovado** (6 amostras e o HTML adversarial B3):

- 0 `<script>`, 0 atributos `on*=` e 0 `src`/`href` que não sejam `#` ou `data:`.
- Tags presentes: somente `a, article, body, br, circle, dd, div, dl, dt, footer, h1-h4, head, header, html, img, li, link, main, meta, nav, ol, p, path, section, span, strong, style, svg, table, tbody, td, th, thead, title, tr, ul`. O único `<style>` é o template.
- **CSP declarada:** `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'` (`HtmlRenderer.ps1:1129-1131`). `'unsafe-inline'` é necessário para os `style="width:N%"`, cujos valores vêm só de dígitos (`Get-FmpPctWidth`, `:80-87`).
- **CSS:** o template é rejeitado se contiver `<`, `@import` ou `url(` (`:1125`).
- **Assets:**
  - MIME restrito a `image/png` e `image/jpeg`.
  - Caminho restrito a `^embed/[a-z]+\.b64$`.
  - Tamanho exato derivado de `bytes` e conferido.
  - Prefixo mágico (`iVBORw0KGgo` / `/9j/`) e alfabeto Base64 validados.
  - Teto de 400 KB por asset e 1,5 MB no total (`:202-253`).
  - O conteúdo de imagens não é decodificado. Um PNG corrompido com prefixo e tamanho corretos seria embutido, mas não há vetor de injeção (o alfabeto Base64 não permite fechar o atributo).
- **SVGs:** são estáticos e não recebem dados (`:99-107`).
- **XSS e injeção (B3):** payloads `<script>`, `"><img onerror>`, `'><svg onload>`, `</style><style>`, `javascript:` e `{1}{2}<b>` em nomes de startup, processos, discos, GPU, apps, provedores de evento e limitações de módulo **saíram todos escapados**. Nenhum se tornou markup.
- **Tamanho:** 675–700 KB por laudo, quase todo de assets. Consistente com o relatado (~700 KB).
- **P3:** os valores de template são substituídos em cascata (`Common.ps1:394-402`). Um provedor chamado `{1}{2}<b>x</b>` gera "provider '{1}9<b>x</b>' (ID 9)": confusão de conteúdo, sem XSS (B3).

**Avisos de CSP no Chromium — conclusão:**

- Arquivo de evidência: `.playwright-mcp/console-2026-11-20T16-43-15-442Z.log` (38 linhas).
- Todas as linhas têm a forma: `Connecting to 'http://gc.kis.v2.scr.kaspersky-labs.com/…' violates … "default-src 'none'" … @ http://gc.kis.v2.scr.kaspersky-labs.com/FD126C42-…/main.js:1994`.
- A origem dos avisos é um `main.js` servido pelo domínio do Kaspersky, que tenta se conectar ao seu próprio serviço. O laudo não contém script algum.
- **A atribuição do Sonnet ao antivírus é sustentada por evidência direta (URL de origem no console)**, não apenas plausível. Além disso, a CSP do laudo **bloqueou** a conexão do script injetado: é evidência positiva de que a política funciona como barreira contra exfiltração.
- **Inconclusivo:** o *mecanismo* pelo qual o script executou apesar de `script-src 'none'` (extensão, injeção no nível do navegador ou proxy). Determiná-lo exigiria interferir no antivírus, o que não foi feito.
- O segundo log (`console-2026-11-20T17-06-16-594Z.log`, `127.0.0.1:8000/api/health`) **não pertence ao FIX MY PC**, que não tem JS nem API. É outra aplicação no mesmo perfil do navegador.

---

## 11. Acessibilidade e idiomas

**Estático (verificado):**

- `lang` no `<html>`.
- Link "pular para o conteúdo".
- `<nav aria-label>`, `<main>`, `<section aria-labelledby>`, `<article aria-labelledby>`.
- `<th scope="col">` e `data-label` nos layouts empilhados.
- Imagens decorativas com `alt="" aria-hidden="true"`. O banner tem `alt` localizado.
- SVGs com `aria-hidden` e `focusable="false"`.
- A severidade usa ícone com **forma distinta** e texto, não só cor.
- O medidor tem texto alternativo (`.sr`).

**Contraste** (WCAG 2.x, tokens de `style.css:7-38`):

| Par | Razão |
|---|---:|
| muted/branco | 5,73 |
| muted/bg | 5,05 |
| warn/warn-soft | 6,45 |
| ok/ok-soft | 6,13 |
| bad/bad-soft | 6,19 |
| on-navy-soft/navy | 7,89 |
| azul/branco | 6,02 |

Todos ≥ 4,5:1 (AA).

**Impressão:** `@page A4`. O banner, a navegação e o rodapé de tela são ocultados. A **faixa "sintético" permanece**. `break-inside: avoid` em achados e cartões. Nenhum bloco de evidência, limitação ou cobertura é ocultado em `@media print`. **O CSS de impressão não altera a interpretação.**

- **P3:** o rodapé de página está em inglês fixo (`style.css:282`).
- **P3:** não há `prefers-color-scheme`/`forced-colors`. Alto contraste do Windows **não testado**.

**Responsividade 320–1440 px:** os breakpoints em 900/640/360 px, `overflow-wrap:anywhere` em `dd`/`td` e `.scroll-x` sugerem um layout sem overflow, **mas não foi verificado em navegador nesta auditoria** (§2).

**Defeito conhecido de PT-BR — extensão real (FMP-04, P2).** No laudo PT-BR da fixture demo aparecem 7 textos em inglês (B8). Na base de código, as fontes são:

- **34** literais distintos de limitação em `Rules.ps1`, gravados em `checks[].limitations`/`findings[].limitations` e renderizados crus (`HtmlRenderer.ps1:378-381`);
- **22** chamadas de `Add-FmpLimitation` nos coletores, com `key` técnica e `detail` em inglês, renderizados como `[módulo] chave - detalhe` (`HtmlRenderer.ps1:998-1003`);
- **2** limitações da nota (`HealthScore.ps1:158-161`), renderizadas em `HtmlRenderer.ps1:1009-1011`.

**Correção localizada e segura (preserva o determinismo):**

1. **Não alterar** o conteúdo atual do JSON. Os textos em inglês continuam como valor canônico e determinístico.
2. Nas regras, devolver junto de `Limitations` um array paralelo `LimitationKeys` (ex.: `rules.os.w10_eol.lim.snapshot`) e gravá-lo em `checks[].limitationKeys`.
3. No renderizador, para cada limitação, usar `Get-FmpText` com a chave. Se a chave faltar, cair no texto inglês original, que é o comportamento atual (sem regressão).
4. Para os limites de módulo, usar a `key` já existente: `limit.<key>` no locale, com fallback para `detail`. Para a nota, usar `score.limitation.1` e `score.limitation.2`.
5. Acrescentar ao teste de i18n uma asserção de que todo `limitationKeys`/`limits[].key` emitido por regras e fixtures existe nos dois locales.

---

## 12. Compatibilidade Windows/PowerShell

| Item | Observado |
|---|---|
| Host desta auditoria | Windows 11 Enterprise 10.0.26300 |
| Windows PowerShell | 5.1.26100.9818 Desktop — suítes 100% verdes |
| PowerShell 7 | **ausente; não validado** |
| StrictMode 3.0 | ativo no CLI, nos testes e no harness |
| Arrays unitários e vazios | tratados com `@()` e retornos com vírgula (`Common.ps1:98,195`) |
| Datas | `InvariantCulture` + `RoundtripKind`; hotfix com formatos explícitos (`Advanced.ps1:9-25`) |
| Números | `TryParse` Invariant, NaN/Inf → null (`Common.ps1:42-57`) |
| Timeouts | `-OperationTimeoutSec 15` em todo CIM |
| WOW64 | detectado e documentado como limitação |

**Riscos PS7 (não testados):**

- `ConvertFrom-Json` no PS7 converte strings ISO em `DateTime`. O código aceita os dois tipos (`Common.ps1:229`), mas o caminho não está coberto por testes.
- `ConvertTo-Json` no PS7 não escapa `<`. Sem impacto, porque o JSON nunca é inserido em HTML sem `HtmlEncode` (`HtmlRenderer.ps1:373-374`).

**Coletores:** a revisão de código não encontrou caminho em que um coletor declare `pass` depois de falhar a consulta **essencial** daquele subcheck. Há falhas de consultas **auxiliares** engolidas, sem impacto em regras: `Performance.ps1:30,71` (`Win32_OperatingSystem`, `Win32_Processor`) e `Storage.ps1:115-117` (correspondência volume↔disco). O módulo continua `ok` e as regras dependentes caem para `unknown` → P3 (FMP-P3-11).

**Harness offline:** remove o provedor Registry, autoload, aplicativos e scripts, e coloca sentinelas que lançam erro em 25 cmdlets (`Collector.Tests.ps1:57-107`). O isolamento é **no nível de cmdlet**: chamadas .NET estáticas ainda leem valores do ambiente do host (`[Environment]::GetFolderPath`, `DriveInfo`, `$env:SystemDrive`). São leituras benignas, mas a frase "never queries the real host" é ligeiramente exagerada (FMP-P3-13).

**Coletores não estão homologados em hardware real** só porque passam nas fixtures.

---

## 13. Distribuição e licenciamento

| Item | Situação |
|---|---|
| `SKILL.md` | Regras corretas: consentimento, só `fixmypc.ps1`, só o JSON sanitizado. Declara `license: MIT` (`SKILL.md:4`). |
| Adaptadores Claude e Codex | Usam `-NoProfile -NonInteractive … -AcceptReadOnlyPolicy` condicionado ao acordo do usuário (FMP-09). |
| READMEs | Prometem pesos "Startup 15" (FMP-01). |
| Segredos e caminhos pessoais | Nenhum segredo encontrado. **Caminho absoluto local** em `.impeccable/hook.cache.json` (`<workspace>\\…`). |
| Artefatos acidentais | `.playwright-mcp/*.log` (URLs de sessão do Kaspersky com GUIDs, que revelam o AV usado), `.impeccable/`, `.commandcode/`, `IMPLEMENTATION-REPORT.md`, `docs/screenshots` (~4 MB) e originais PNG em `assets/branding` + `assets/report` (~10,6 MB) que não são usados em execução. Não há `.gitignore` nem manifesto de empacotamento (FMP-P3-03). |
| Marca Windows | **Banner e ícone** mostram o logotipo de quatro painéis do Windows no monitor (`assets/optimized/report/fixmypc-report-banner.jpg`, `assets/optimized/branding/fixmypc-icon.png` e originais). Não há aviso de "não afiliado à Microsoft" (FMP-10, P2). |
| Licença | `LICENSE` MIT e `SKILL.md:4` presentes, **não confirmados pelo proprietário → decisão pendente**. Esta auditoria não escolhe nem altera a licença. |

---

## 14. Vulnerabilidades e defeitos

### P0 — Bloqueantes

Nenhum.

### P1 — Alto

#### FMP-01 · Pontuação estruturalmente enganosa (peso de Inicialização inatingível, tetos inalcançáveis)

- **Arquivos:**
  - `rules/rules.json:3-9` (pesos), `:185-247` (todas as regras de startup e do SO avançado só em `full`, penalidade 0);
  - `src/analysis/HealthScore.ps1:54,78,93,101-114`;
  - `README.md:36`, `README.pt-BR.md:32`, `docs/methodology.md:42`.
- **Descrição:** os pesos funcionam só como tetos. Nenhuma regra-base penaliza Inicialização. Armazenamento, Desempenho e SO não alcançam seus tetos. A nota mínima possível é 39.
- **Causa:** a decisão de manter a métrica-base idêntica entre os modos excluiu da base todas as regras de startup, mas o peso de 15 foi mantido. As penalidades por regra não foram calibradas contra os pesos.
- **Cenário reproduzível:** `docs/reviews/opus-5.5-evidence/Adversarial.Tests.ps1`, casos B0, B1 e B2. Sobre `win11-healthy.json`: `physicalDisks[0].healthStatus='Unhealthy'`, `smart.items[0].predictFailure=$true` e 12 eventos `disk` 7 em 48 h, em modo simple.
- **Impacto:** um PC com falha de disco iminente, reportada pelo próprio Windows, recebe **88/100** com status `ok` e confiança `high`. O medidor fica a 88%. Um usuário, ou um agente que resume o laudo, tende a concluir "PC em bom estado". A categoria Inicialização contribui 15 pontos sem nenhuma evidência.
- **Evidência:** `adversarial-results.txt`:
  - `B1-failing-disk | score=88 status=ok conf=high deduction=12`
  - `B2-worst-case | score=39 … perCategory=storage-22,events-25,performance-8,startup-0,os-6`
  - `B0-categories | … startup:0/0 rem=15`
- **Recomendação** (escolher uma, com decisão do proprietário):
  - (a) Excluir do denominador as categorias com `applicableChecks = 0` e renormalizar a nota, de modo que Inicialização sem regras-base não some pontos.
  - (b) Introduzir um **gating por severidade**: uma regra `storage.health` comprovada limita a nota a um teto (ex.: ≤ 49) e força o status `attention_required`, exibido em destaque.
  - (c) Recalibrar as penalidades para que cada categoria possa atingir seu peso. Atualizar README e metodologia para descrever o comportamento real em qualquer das opções.
- **Teste de regressão proposto:**
  - Fixture "disco falhando" → nota ≤ limite acordado **ou** status diferente de `ok`.
  - Asserção estática: toda categoria com peso > 0 tem ≥ 1 regra-base com penalidade > 0, ou é excluída do denominador.
  - Asserção: para cada categoria, a soma das penalidades máximas após dedupe ≥ peso, ou o comportamento documentado.

### P2 — Médio

#### FMP-02 · Scanner AST aceita setters de propriedade e métodos de instância "por nome"

- **Arquivo:** `src/security/ReadOnlyPolicy.ps1:224-226` (atribuição só é sinalizada para `$global:`/`$env:`/…), `:305` (acesso a membro sem invocação sempre aceito), `:95-99` (`Replace`, `Remove`, `Clear`, `Stop`, `Add` aceitos em qualquer tipo).
- **Causa:** a allowlist de membros é baseada em nome, não em tipo. Atribuições a `MemberExpressionAst` não são inspecionadas.
- **Cenário:** snippets A1–A5 aprovados pelo scanner (`scanner_ok=True`):
  - `$p[0].PriorityClass='Idle'`;
  - `.ProcessorAffinity=1`;
  - `$f.IsReadOnly=$true`;
  - `$d.Attributes='Hidden'`;
  - `$f.Replace(dest, backup)` (`FileInfo.Replace` sobrescreve o destino).
- **Impacto:** uma alteração futura, ou um coletor adulterado, poderia mudar prioridade de processo ou atributos e conteúdo de arquivos passando pelo gate que sustenta a promessa "somente leitura". **O código atual não usa esses padrões** (verificado). Por isso é P2 (defesa em profundidade) e não P0.
- **Recomendação:** rejeitar toda `AssignmentStatementAst` cujo lado esquerdo seja `MemberExpressionAst`/`IndexExpressionAst` sobre variável que não seja um `[ordered]@{}`/`@{}`/`List` criado localmente. Na prática, permitir só atribuições a chaves de hashtable e a variáveis simples. Restringir `Replace`, `Remove`, `Clear` e `Stop` aos receptores cujo tipo é inferível como `string`, `StringBuilder`, `List`, `Hashtable` ou `Stopwatch`, ou renomear os usos atuais para helpers internos.
- **Teste de regressão:** os snippets A1–A5 devem resultar em `Ok=$false`.

#### FMP-03 · Valores de caminho não restringidos nos cmdlets de leitura (UNC/SMB, leitura de segredos)

- **Arquivo:** `src/security/ReadOnlyPolicy.ps1:26-36,54-55` (`LiteralPath`/`Path`/`FilterHashtable` aceitos com qualquer valor).
- **Cenário:** A6 `Get-ChildItem -LiteralPath '\\host\share'`, A7 `Get-WinEvent -FilterHashtable @{Path='\\host\s\x.evtx'}` e A8 `Get-Content -LiteralPath '…\.ssh\id_rsa'` são **aprovados**.
- **Impacto:** acesso de rede via SMB (que pode vazar o hash NTLM) e leitura de dados sensíveis sem violar o scanner. O código atual só usa caminhos constantes ou derivados de `GetFolderPath`, com proteção UNC (`Startup.ps1:108`). Mesmo racional do FMP-02.
- **Recomendação:** nos coletores, exigir que os argumentos de caminho sejam `StringConstantExpressionAst` com prefixo `HKLM:\`/`HKCU:\`, ou uma variável produzida por `Get-FmpCheckedPath`. Rejeitar literais que começam com `\\`. Exigir `FilterHashtable` literal sem a chave `Path`.
- **Teste:** A6–A8 devem resultar em `Ok=$false`.

#### FMP-04 · Texto em inglês no laudo PT-BR

- **Arquivos:** `Rules.ps1` (34 literais `Limitations`), `src/collectors/*.ps1` (22 `Add-FmpLimitation`), `HealthScore.ps1:158-161`; renderização em `HtmlRenderer.ps1:378-381,998-1003,1009-1011`.
- **Cenário:** B8 → 7 itens em inglês no laudo PT-BR da `demo-synthetic.json`. Exemplos:
  - "a missing signature is common in legitimate tools; it is NOT evidence of malware";
  - "The score is a review aid…";
  - "[startup] startup_lnk_not_parsed - .lnk targets not resolved".
- **Impacto:** justamente as ressalvas que evitam interpretação errada aparecem em outro idioma para o público PT-BR. As chaves técnicas também ficam expostas.
- **Recomendação e teste:** ver §11. **O suporte PT-BR não está finalizado.**

#### FMP-05 · Rótulos de severidade invertidos nas regras de armazenamento e ordenação resultante

- **Arquivos:** `docs/methodology.md:20-21` ("Recomendado revisar" = nível acima de "Atenção"); `rules.json:35-65`; `HtmlRenderer.ps1:315-320`.
- **Descrição:** `<5% livre` (penalidade 10) = "Atenção", enquanto `<10% livre` (penalidade 6) = "Recomendado revisar". Disco `Unhealthy` (12) = "Atenção", enquanto SMART (8) = "Recomendado revisar".
- **Cenário:** B5, volume do sistema com 3% livre → `storage.low_free_space(review_recommended, pen 6) > storage.disk_space_critical(attention, pen 10)`. A condição mais grave aparece depois e com o rótulo menor, inclusive nas três "observações principais" do resumo.
- **Impacto:** a priorização visual contradiz a penalidade e a gravidade real.
- **Recomendação:** decidir a escala (penalidade ou rótulo) e alinhar `rules.json` e a metodologia. Por exemplo: critical e unhealthy → `review_recommended`, ou inverter a ordem do renderizador junto com a definição dos níveis.
- **Teste:** para cada `dedupeGroup`, a regra de maior penalidade não pode ter um rank de severidade inferior.

#### FMP-06 · `startup.high_count` dispara em praticamente qualquer Windows

- **Arquivos:** `Startup.ps1:204` (todos os serviços `StartMode='Auto'`); `Rules.ps1:438-446` (limiar 30 sobre itens + tarefas + serviços).
- **Cenário:** B6, 90 serviços automáticos e nada mais → `state=finding`. As fixtures usam um único serviço (`win11-healthy.json`), por isso os testes não detectam.
- **Impacto:** o achado "muitos itens de inicialização" aparece em toda máquina real. É informativo, sem penalidade e só de análise, mas gera ruído e induz a desativar serviços.
- **Recomendação:** contar só Run/RunOnce, pastas Startup e tarefas de logon, ou excluir serviços do Windows (por exemplo pelo `PathName` em `%SystemRoot%`, sem abrir arquivos) e criar um limiar separado para serviços.
- **Teste:** fixture realista com cerca de 100 serviços do sistema → `pass`.

#### FMP-07 · "CPU sustentada" baseada em ~4 s

- **Arquivos:** `Performance.ps1:11,77-92` (3 amostras × 2 s); `rules.json:135` (attention, penalidade 4); `Rules.ps1:294-311`.
- **Cenário:** B7, média de 95% → achado `attention`, penalidade 4, nota 96 com status `ok`.
- **Impacto:**
  - Um pico de quatro segundos, que pode ser causado pela própria coleta (WMI e PowerShell), é rotulado como "sustentado" e penaliza a nota.
  - A limitação existe, mas está em inglês (FMP-04).
- **Recomendação:**
  - rebaixar para `info` com penalidade 0;
  - ou exigir janela ≥ 30 s e excluir o processo do próprio auditor;
  - renomear para "CPU elevada durante a amostragem".
- **Teste:** 3 amostras altas não devem penalizar.

#### FMP-08 · Sanitização deixa passar SIDs e identificadores por usuário

- **Arquivo:** `src/security/Privacy.ps1:56-90` (não há padrão para `S-1-5-21-…`), `:132-134` (identificadores só em campos listados).
- **Cenário:** B4. Tarefa `OneDrive Reporting Task-S-1-5-21-1004336348-…-1001`, serviço `CDPUserSvc_4a7f3c` e serial anexado a um nome de modelo → todos presentes no JSON **e** no HTML sanitizados. `DESKTOP-AUDIT01` e `jsilva` foram corretamente removidos.
- **Impacto:** o artefato "compartilhável" contém identificadores estáveis da conta/máquina (o SID do domínio local é único por instalação). É plausível em tarefas de logon de atualizadores por usuário (Edge, Google, OneDrive). A presença real precisa ser confirmada na homologação.
- **Recomendação:** acrescentar as regexes `\bS-1-5-21(?:-\d+){3,4}\b` → `<SID>` e `_[0-9a-f]{4,8}\b` em nomes de serviço → `_<LUID>`. Aplicar `PrivateIdentifiers` a **todas** as strings, não apenas a uma lista.
- **Teste:** fixture B4 → nenhuma ocorrência dos identificadores no sanitizado.

#### FMP-09 · Consentimento dos adaptadores é declaratório

- **Arquivos:** `adapters/claude/README.md:24`, `adapters/codex/AGENTS.md:13`, `SKILL.md:25-28,45-46`.
- **Descrição:** `-AcceptReadOnlyPolicy` é aceito de qualquer chamador. O gate técnico não distingue um humano de um agente que ignorou a instrução.
- **Cenário:** um agente executa o comando documentado sem perguntar ao usuário → a coleta real começa.
- **Impacto:** o risco é de coleta sem consentimento **mediada por instrução de prompt**, mas continua somente leitura e local. É limitação de design, não falha de código.
- **Recomendação:**
  - documentar explicitamente no README e no SKILL que o consentimento em execuções de agente depende do agente;
  - opcionalmente exigir um token de consentimento gerado numa execução interativa curta (`-IssueConsentToken`), válido por N minutos e por um único `OutDir`.
- **Teste:** na opção do token, `-AcceptReadOnlyPolicy` sem token válido em host não interativo → exit 3.

#### FMP-10 · Uso da identidade visual do Windows nos assets

- **Arquivos:** `assets/optimized/report/fixmypc-report-banner.jpg`, `assets/optimized/branding/fixmypc-icon.png`, `assets/optimized/embed/{banner,icon}.b64` e originais em `assets/branding`, `assets/report`.
- **Descrição:** o logotipo de quatro painéis do Windows aparece no monitor do banner e do ícone embutidos em **todo** laudo. Não há declaração de não afiliação.
- **Impacto:** risco de violar as diretrizes de marca da Microsoft e de sugerir endosso. Bloqueia a distribuição pública, não a homologação.
- **Recomendação:** substituir por um ícone genérico de monitor, adicionar "Not affiliated with or endorsed by Microsoft. Windows is a trademark of Microsoft Corporation." no README e no rodapé, e passar por revisão jurídica.
- **Teste:** item manual de checklist de release.

### P3 — Baixo

| ID | Arquivo:linha | Descrição | Recomendação |
|---|---|---|---|
| P3-01 | `Common.ps1:394-402` | Substituição de placeholders em cascata (B3: `'{1}9<b>x</b>'`). Sem XSS. | Substituição em passagem única via regex `\{(\d+)\}`. |
| P3-02 | `HealthScore.ps1:114` | Arredondamento bancário. | `[Math]::Round(x, 0, [MidpointRounding]::AwayFromZero)`. |
| P3-03 | raiz; `fixmypc.ps1:151` | Não há `.gitignore` nem manifesto de pacote. Artefatos de desenvolvimento no workspace (`.playwright-mcp` com URLs de sessão do Kaspersky, `.impeccable` com caminho absoluto, `.commandcode`). ~10,6 MB de PNG originais. O `out\` padrão fica dentro da pasta da skill e, portanto, do repositório do projeto do usuário. | Lista explícita de inclusão no pacote. `.gitignore` com `out/`, `.playwright-mcp/`, `.impeccable/`, `.commandcode/`. `OutDir` padrão em `%LOCALAPPDATA%\FixMyPC\…`. |
| P3-04 | `tests/Run.Tests.ps1:54` (e `Visual.Tests.ps1:54`, que usa o mesmo padrão) | As suítes escrevem em `out\fmp-*` dentro do projeto. Depois da execução, a cópia mantinha `out\fmp-tests-<guid>` com 47 arquivos. Não sobrou pasta `fmp-visual-tests-*`. | Usar `%TEMP%` ou documentar a limpeza. |
| P3-05 | `tests/Run.Tests.ps1:599-603` | As 194 asserções incluem **2 asserções agregadas** (Collector e Visual inteiras). O total distinto é **192 + 85 + 193 = 470**. "85 incluídos na integrada" significa 1 asserção. | Relatar as contagens separadamente. |
| P3-06 | fixtures vs `Advanced.ps1:283-286` | `advanced.signatures.status='ok'` nas fixtures é inalcançável em execução real. `startup.unsigned_autostart` nunca é avaliada de verdade. | Alinhar as fixtures ao contrato real ou remover a regra. |
| P3-07 | `Privacy.ps1:100` vs `Advanced.ps1:248,275` | Corte de 150 itens no sanitizado sem marcar `truncated`. | Registrar `sanitizedTruncated`. |
| P3-08 | `Events.ps1:116` | `Win32_ReliabilityRecords` + `Select -First 100` sem ordenação: pode exibir os registros mais antigos. | Ordenar por `TimeGenerated` desc antes de cortar. |
| P3-09 | `rules.json:26` | Fim de suporte do 25H2 = `2027-10-13` (quarta-feira). O padrão da Microsoft é a 2ª terça-feira (`2027-10-12`). **Verificar** na página oficial. | Corrigir após confirmação. |
| P3-10 | `rules.json` (os.outdated_patch) | Limiar de 365 dias é frouxo, e `pass` sugere "atualizado". | Estado `pass` com texto "nenhum hotfix antigo detectado" ou limiar de 60–90 dias. |
| P3-11 | `Performance.ps1:30,71`; `Storage.ps1:115-117` | Falhas auxiliares engolidas mantêm o módulo `ok`. | Registrar `Add-FmpLimitation` nesses `catch`. |
| P3-12 | `fixmypc.ps1:297-300` | Um conjunto parcial de artefatos pode ficar após falha. | Escrever num subdiretório temporário e renomear o diretório no fim. |
| P3-13 | `tests/Collector.Tests.ps1:1-8` | O harness não bloqueia leituras .NET estáticas do ambiente. | Ajustar a documentação ou envolver os helpers com mocks. |
| P3-14 | `style.css:282`; sem `forced-colors` | Rodapé de impressão em inglês. Alto contraste não tratado nem testado. | Localizar via atributo; adicionar `@media (forced-colors: active)`. |
| P3-15 | `Advanced.ps1:39`; assets | `devices.problem_codes` conta os códigos 22 e 45. O banner com escudo e "check" verdes aparece mesmo em laudos com achados graves ou nota indisponível. `ReadOnlyPolicy.ps1:149-160` atribui papéis por regex no caminho absoluto (falha fechada nos casos testados). | Filtrar 22/45. Banner neutro. Usar o caminho relativo à raiz. |

---

## 15. Testes executados

Ambiente: Windows 11 Enterprise 10.0.26300, Windows PowerShell **5.1.26100.9818 Desktop**. PowerShell 7 **ausente**. Execução numa **cópia** do projeto em `%TEMP%\claude\…\scratchpad\fmp` (robocopy sem `.playwright-mcp` e `out`), com `-ExecutionPolicy Bypass` no escopo do processo (sem alteração de política do sistema).

| Comando | Resultado observado | Consulta o host? |
|---|---|---|
| `tests\Run.Tests.ps1` | **194 passaram, 0 falharam**, exit 0, 68 s | Não. Usa fixtures. Os testes de CLI usam o projeto-espelho com coletores `throw` (`:544-558`). Execuções reais de `fixmypc.ps1` só com `-Fixture` ou `-ValidateOnly` (`:379,389`). |
| `tests\Collector.Tests.ps1` | **85 passaram, 0 falharam**, exit 0 | Só leituras .NET de ambiente (P3-13). Cmdlets de sistema substituídos por sentinelas. |
| `tests\Visual.Tests.ps1` | **193 passaram, 0 falharam**, exit 0 | Não. |
| `fixmypc.ps1 -ValidateOnly` | **PASS**: 15 arquivos, 0 violações, 337 chaves por locale, `rules.json` OK | Não carrega coletores. |
| `docs/reviews/opus-5.5-evidence/Adversarial.Tests.ps1` (novo, isolado) | 17 snippets de scanner (8 aprovados indevidamente: A1–A8; 9 bloqueados corretamente: C1–C9) e 10 cenários de pipeline (B0–B9) | Não. Não carrega `src\collectors`. Os snippets só passam pelo parser. |
| Varredura das 6 amostras HTML | 0 script, 0 on*, 0 URL externa, CSP idêntica | — |
| Navegador | **Não executado** (Playwright bloqueado por outra instância) | — |

Para reproduzir os testes adversariais:

```powershell
powershell -NoProfile -NonInteractive -File docs\reviews\opus-5.5-evidence\Adversarial.Tests.ps1 -Root <cópia-do-projeto> -Work <pasta-temporária>
```

---

## 16. Evidências

Arquivo `docs/reviews/opus-5.5-evidence/adversarial-results.txt` (saída integral). Linhas-chave:

```
A1-priority-setter | scanner_ok=True violations=
A5-fileinfo-replace | scanner_ok=True violations=
A6-unc-childitem | scanner_ok=True violations=
C1-remove-item | scanner_ok=False violations=hard_banned_command
B0-categories | storage:5/5 rem=30; events:5/5 rem=25; performance:3/3 rem=20; startup:0/0 rem=15; os:2/2 rem=10
B1-failing-disk | score=88 status=ok conf=high deduction=12 findings=storage.disk_health_unhealthy,storage.smart_predict_failure,storage.disk_event_errors
B2-worst-case | score=39 status=ok deduction=61 perCategory=storage-22,events-25,performance-8,startup-0,os-6
B3-injection | … scriptTags=0 styleTags=1   (on*= só aparece como texto escapado; 0 tags com atributo on*)
B4-survives | S-1-5-21-1004336348 json=True html=True
B4-survives | DESKTOP-AUDIT01 json=False html=False
B5-order | storage.low_free_space(review_recommended,pen 6) > storage.disk_space_critical(attention,pen 10)
B6-startup-high-count | state=finding
B7-cpu-burst | severity=attention penalty=4 score=96 status=ok
B8-english-in-ptBR | count=7
```

Log CSP (trecho com tokens longos suprimidos):

```
[ERROR] Connecting to 'http://gc.kis.v2.scr.kaspersky-labs.<…>' violates the following Content Security Policy
directive: "default-src 'none'" … The action has been blocked.
@ http://gc.kis.v2.scr.kaspersky-labs.com/FD126C42-EBFA-4E12-B309-BB3FDD723AC1/main.js?<…>:1994
```

---

## 17. Correções necessárias, por prioridade

1. **Antes da distribuição (obrigatórias):**
   1. FMP-01: redesenhar ou documentar o modelo de nota. Recomendado: renormalizar categorias sem regras-base e aplicar gating para saúde de disco comprovada.
   2. FMP-04: localizar limitações via chaves, com fallback para o inglês.
   3. FMP-10: retirar o logotipo do Windows e adicionar a declaração de não afiliação.
   4. Decisão de licença pelo proprietário.
2. **Antes ou durante a homologação:**
   1. FMP-02/03: endurecer o scanner (setters, caminhos).
   2. FMP-05: alinhar a escala de severidade.
   3. FMP-06: corrigir a contagem de inicialização.
   4. FMP-07: rebaixar a regra de CPU.
   5. FMP-08: adicionar redação de SID/LUID.
   6. FMP-09: documentar o limite do consentimento de agentes.
3. **Higiene (P3):** `.gitignore` ou manifesto de pacote, `OutDir` fora da pasta da skill, limpeza dos testes, deriva das fixtures e os demais itens da tabela P3.

Cada correção deve vir com o teste de regressão indicado em §14.

---

## 18. Riscos residuais (mesmo após as correções)

- A allowlist estática não prova o comportamento interno de provedores WMI, SMP de fabricantes, RAC e Defender.
- A precedência de alias, função ou perfil e o autoload a partir do diretório de módulos do usuário (mitigados por `-NoProfile`).
- TOCTOU entre a verificação de reparse point e a abertura do arquivo, contra um processo local do mesmo usuário.
- ACL herdada do diretório de saída: quem lê a pasta-pai lê o laudo.
- Nomes de produtos, processos e serviços continuam no JSON sanitizado e podem identificar software instalado (já declarado em `Privacy.ps1:153-156`).
- Scripts injetados por antivírus executam na origem do laudo. A CSP bloqueou a rede no caso observado, mas o script lê o DOM.
- O consentimento em execuções por agente depende do agente.

---

## 19. Requisitos para a homologação Windows

Executar somente com autorização explícita, em máquinas de teste dedicadas ou VMs, nunca no host desta auditoria sem pedido:

1. **Matriz:**
   - Windows 10 22H2 e Windows 11 24H2/25H2;
   - usuário padrão **e** administrador;
   - Windows PowerShell 5.1 **e** PowerShell 7.4+;
   - x64, e um caso de PowerShell 32-bit (WOW64).
2. **Prova de somente leitura:**
   - snapshot da VM antes;
   - comparação de registro (HKLM/HKCU), serviços, tarefas, arquivos de `%SystemRoot%`/`%ProgramData%`/perfil e políticas antes e depois;
   - ProcMon filtrado por `powershell.exe`/`WmiPrvSE.exe` com `WriteFile`/`RegSetValue`/`RegCreateKey`/`TCP Connect` → somente escritas no `OutDir`;
   - monitor de rede → zero conexões.
3. **Consentimento:**
   - rodar sem flags num host não interativo → exit 3 e nenhuma consulta (verificar no ProcMon);
   - recusa interativa → exit 3.
4. **Estados reais:** usuário padrão (SMART → `access_denied`, Security → `access_denied`), RAC desabilitado, Defender substituído por AV de terceiros, NVMe sem `MSStorageDriver`, disco USB removível e Storage Spaces.
5. **Privacidade:** procurar no JSON e no HTML sanitizados o nome do computador, do usuário, o SID, o domínio, o e-mail e o caminho do perfil (depois do FMP-08).
6. **Desempenho:** duração total e pico de memória em modo Completa, com `Win32_PnPSignedDriver` e logs com mais de 2000 eventos.
7. **Laudo:** renderizar em Edge e Chrome (com e sem o antivírus do usuário), Firefox, larguras de 320 a 1440 px, impressão A4, alto contraste do Windows e leitor de tela (Narrador/NVDA).
8. **Critério de aceite:** usar estados, cobertura e achados, **não a nota**, até a correção do FMP-01.

---

## 20. Veredito final

### **APROVADO COM RESSALVAS**

**Justificativa:**

- **Nenhum P0.** A coleta é somente leitura no nível do código. O consentimento é exigido antes de qualquer coletor ser carregado. `-Yes` e fixtures inválidas falham fechado. Não há rede, script nem referência externa no laudo. A escrita é confinada (com o risco residual TOCTOU declarado). Os testes de CLI não alcançam coletores reais.
- **Um P1 aberto (FMP-01, pontuação).** É comprovado e relevante para a qualidade do diagnóstico, mas **não compromete o uso seguro**: não modifica o sistema, não coleta sem consentimento e não expõe dados. Por isso não justifica BLOQUEADO pelos critérios definidos. Também impede o veredito "Aprovado para homologação controlada", que exige zero P1 aberto.
- **Condições desta aprovação:**
  1. A homologação controlada pode testar coletores, estados, privacidade e o caráter somente leitura. A nota **não** pode ser critério de aceite nem ser apresentada a usuários finais até a correção do FMP-01.
  2. O suporte PT-BR **não** está finalizado (FMP-04).
  3. Os coletores **não** estão homologados em hardware real.
  4. PowerShell 7 **não** foi validado.

**Esta classificação não aprova distribuição pública.** A publicação exige:

- corrigir FMP-01, FMP-04 e FMP-10;
- a decisão de licença pelo proprietário;
- concluir a homologação Windows real autorizada (§19).
