# FIX MY PC — Correção dos achados FMP-01 e FMP-04

- **Responsável:** Claude Opus 5.5 (`claude-opus-5-5`)
- **Data:** 2026-11-20
- **Base:** `docs/reviews/CLAUDE-OPUS-5.5-FINAL-AUDIT.md`
- **Escopo:** somente FMP-01 (P1, pontuação) e FMP-04 (P2, limitações em inglês no laudo PT-BR).

**Os demais achados da auditoria final continuam abertos:** FMP-02, 03, 05, 06, 07, 08, 09, 10 e todos os P3. A auditoria **não** está encerrada.

**Restrições respeitadas:**
- Nenhuma auditoria real do Windows e nenhum uso de `-AcceptReadOnlyPolicy`.
- Nenhuma consulta a hardware, processos, serviços, eventos, registro ou SMART do anfitrião.
- Somente fixtures. As suítes rodaram numa cópia espelhada do projeto no scratchpad.
- Nenhum commit, push ou publicação.
- Nenhuma rede, JavaScript ou dependência nova no HTML.
- O consentimento não mudou. Nos coletores, mudaram apenas 6 chamadas de `Add-FmpLimitation`, que ganharam metadados de localização.

**Skills usadas:** `superpowers:systematic-debugging`, `superpowers:test-driven-development` e `superpowers:verification-before-completion`, mais `security-and-hardening`, que já tinha sido carregada na auditoria. As mudanças tocam análise e renderização, mas não tocam sanitização nem execução. A revisão de segurança foi feita como verificação dirigida do HTML gerado (§5.4).

---

## 1. Causas

### FMP-01 — pontuação enganosa

Causas confirmadas pela evidência da auditoria (casos B0, B1 e B2) e pela leitura de `HealthScore.ps1` antes da mudança:

1. **Categoria sem regra-base somava pontos automaticamente.**
   - A nota era `100 − Σ deduções`, com todos os pesos no denominador implícito.
   - Inicialização (peso 15) só tem regras exclusivas da Completa, com penalidade 0 (`rules.json`, `modes: ["full"]`). Por isso nunca podia perder pontos.
   - O mesmo acontecia com qualquer categoria cujas verificações terminassem todas inconclusivas: o peso inteiro continuava valendo como saúde.
2. **Não havia mecanismo de gravidade.**
   - A penalidade máxima de armazenamento após o dedupe é 22, e o grupo `storage.health` vale no máximo 12.
   - Um disco `Unhealthy` com SMART prevendo falha recebia 88 com `status: ok` e `confidence: high`.
3. **Disponibilidade, confiança e risco estavam misturados.**
   - O JSON só tinha `status` (disponibilidade) e `confidence` (qualidade dos dados).
   - Não havia campo dizendo que o computador tinha um problema grave, e "confiança alta" era lida como "PC saudável".

### FMP-04 — inglês no laudo PT-BR

- **Regras:** 34 textos de limitação em inglês eram gravados em `checks[]/findings[].limitations` e renderizados literalmente (`HtmlRenderer.ps1`, bloco de achados).
- **Coletores:** 22 pontos de `Add-FmpLimitation` produziam `key` técnica e `detail` em inglês. O renderizador mostrava `[módulo] chave - detalhe`.
- **Pontuação:** 2 limitações fixas em inglês em `HealthScore.ps1`.
- **Erros de módulo:** apareciam como `[módulo] onde: <Redacted>`, expondo chaves técnicas. O mesmo acontecia com os ids e status de módulo na seção Metodologia.

**Bug encontrado durante a implementação** (diagnosticado com reprodução isolada antes de corrigir): no PowerShell 5.1, `[string](<comando sem saída>)` resulta em `$null`, não em `''`. A comparação `$lk -eq ''` era falsa e o fallback para `key` nunca rodava. A correção usa `[string]::IsNullOrEmpty` e o motivo ficou comentado no código.

---

## 2. Alterações efetuadas

### FMP-01

| Arquivo | Mudança |
|---|---|
| `src/analysis/HealthScore.ps1` | Elegibilidade por categoria (`eligible`, `excludedReason`: `no_base_rules`, `no_evidence` ou `zero_weight`). Renormalização sobre o peso elegível. `riskLevel` + `riskReasons`. Limite por gravidade (`uncappedScore`, `scoreCap`, `capped`). `eligibleWeight`. Validação de `riskGates.critical.scoreCap`. `status = unavailable` quando nenhuma categoria é elegível. |
| `src/analysis/Rules.ps1` | `storage.smart_predict_failure` (achado) → `Gate = critical`. `storage.disk_health_unhealthy` → `Gate = critical` **somente** se algum item tiver `Unhealthy` (`Warning` não). `Invoke-FmpRules` grava `riskGate: critical` no achado, e só para regras-base. |
| `rules/rules.json` | `riskGates.critical.scoreCap = 49` e `scoringNotes` atualizadas. Nenhuma regra ou penalidade nova. |
| `src/reports/HtmlRenderer.ps1` | Resumo com "Risco diagnóstico" separado da nota. Aviso para risco crítico. Aviso "Nota limitada a 49 (sem o limite, seria N)". Categorias fora da nota sem barra e com motivo. Nota sobre a renormalização. |
| `templates/style.css` | Classes `.risk`, `.risk.critical` e `.risk.elevated`, só com tokens existentes. "Nenhum risco detectado" é neutro, não verde. |
| `locales/*.json` | Rótulo "Confiança dos dados". Textos de risco, limite e renormalização. `score.explanation` revisado. Rótulos de categoria fora da nota. |
| `schemas/diagnostic.schema.json` | Novos campos de `healthScore` (`riskLevel` passa a ser obrigatório), `categories[].eligible/excludedReason`, `findings[].riskGate`. |
| `docs/methodology.md`, `README.md`, `README.pt-BR.md`, `CHANGELOG.md` | Algoritmo, deduções máximas alcançáveis, limite e justificativa. |

### FMP-04

| Arquivo | Mudança |
|---|---|
| `src/analysis/Rules.ps1` | Tabela `$script:FmpRuleLimitationKeys` (34 textos canônicos → chave `lim.*`). `Get-FmpRuleLimitationKeys`. `checks[]` e `findings[]` ganham `limitationKeys` paralelo. **O texto canônico em `limitations` fica inalterado.** |
| `src/analysis/HealthScore.ps1` | `limitationKeys` paralelo às 2 limitações da nota (`score.limitation.*`). |
| `src/analysis/Evidence.ps1` | `Add-FmpLimitation` aceita `-LocaleKey` (para chaves com sufixo dinâmico) e `-Values` (placeholders). `key` e `detail` permanecem canônicos. |
| `src/collectors/Events.ps1`, `Performance.ps1`, `Startup.ps1` | 6 chamadas receberam `-LocaleKey` ou `-Values` (`events_truncated_<log>`, `cpu_short_window`, `startup_items_truncated`, `startup_folder_network_<x>`, `startup_folder_skipped_<x>`, `startup_services_truncated`). Nenhuma consulta foi alterada. |
| `src/reports/HtmlRenderer.ps1` | `Get-FmpOptionalText`, `Get-FmpLocalizedLimitation` (fallback seguro: texto canônico, nunca a chave) e `Get-FmpModuleName`. Limitações de achados, de módulos e da nota localizadas. Erros de módulo viram uma frase localizada; o detalhe técnico fica no JSON. Ids e status de módulo localizados na Metodologia. |
| `locales/*.json` | +77 chaves em cada idioma, com paridade (337 → 414): 34 `lim.*`, 22 `limit.*`, 2 `score.limitation.*`, 9 `module.*`, 2 genéricas e 8 de FMP-01. |
| `tests/fixtures/demo-synthetic.json` | A limitação `cpu_short_window` ganhou `"values": [6]`, o mesmo contrato que o coletor real agora emite. |

**Amostras sintéticas regeneradas**, somente via `-Fixture` e `tools/Render-Samples.ps1`, geradas no scratchpad e copiadas:
- `samples/demo-report.html` e `samples/demo-report.en.html`;
- `samples/demo-diagnostic-sanitized.json` e `samples/demo-diagnostic-internal.json` (re-indentados em 2 espaços, como os anteriores);
- `samples/visual/{provisional,unavailable}.{pt-BR,en}.html`.

---

## 3. Justificativa matemática da nova nota

Sejam `w_c` o peso, `d_c` a dedução após dedupe e teto (`0 ≤ d_c ≤ w_c`), e `E` o conjunto de categorias elegíveis:

```
c ∈ E  ⇔  w_c > 0  ∧  ∃ regra-base de c com penalidade > 0  ∧  ≥ 1 verificação-base de c em pass/finding
W_E    = Σ_{c∈E} w_c                        (eligibleWeight)
bruta  = round( 100 · Σ_{c∈E} (w_c − d_c) / W_E )      (uncappedScore)
nota   = min(bruta, ⌊cap⌋)  se riskLevel = critical, senão bruta
nota   = null (status unavailable) se W_E = 0, cobertura < 35% ou falha de módulo-base
```

**Propriedades:**

1. **Sem pontos gratuitos.** Uma categoria fora de `E` não entra no numerador nem no denominador. Antes, entrava com `w_c − 0`.
2. **Compatível com a fórmula anterior.** Se todas as categorias fossem elegíveis (`W_E = 100`), `bruta = 100 − Σ d_c`, exatamente a fórmula antiga.
3. **Limitada e monotônica.** `0 ≤ bruta ≤ 100`. Aumentar qualquer `d_c` nunca aumenta a nota.
4. **Ausência de evidência não penaliza.** Estados inconclusivos não geram `d_c`. Também não adicionam peso a `E` quando a categoria inteira fica sem evidência.
5. **Comparabilidade entre modos.** `E`, `d_c` e os gatilhos só usam regras-base (`modes` ∋ `simple`). Regras só da Completa continuam com penalidade 0 e nunca definem `riskGate` (`Invoke-FmpRules` ignora o gate de regras `analysisOnly`).
6. **Limite por gravidade.** Sem o limite, a pior falha de armazenamento comprovada (grupo `storage.health`, 12 pontos) deixaria a nota em 86. Esse problema era estrutural: o dedupe e o teto por categoria impedem que ela pese mais.
   - Em vez de inflar penalidades (o que seria proibido pelo pedido), um gate determinístico limita a nota a 49 quando o próprio Windows (`Unhealthy`) ou o firmware do disco (`PredictFailure=true`) declara falha.
   - 49 < 50: a nota fica abaixo da metade da escala e não pode ser lida como saúde normal ou excelente. O valor é configurável em `rules.json`, validado como número entre 0 e 100 e aplicado com `Floor`, para manter o inteiro exigido pelo schema.
7. **Separação de eixos.**
   - `status` diz se há evidência suficiente para apresentar uma nota.
   - `confidence` diz quão completos são os dados.
   - `riskLevel` diz o que os achados-base comprovam (`critical` / `elevated` / `none_detected` / `undetermined`).
   - Uma falha comprovada continua `critical` mesmo quando a nota está indisponível.

**Dedução máxima alcançável** com as regras atuais (documentada, não alterada): Armazenamento 22/30, Eventos 25/25, Desempenho 8/20, Sistema 6/10. Inicialização fica sempre fora (sem regra-base). Com todas as regras-base em achado, a nota é `round(100·(85−61)/85) = 28`. Nenhuma regra artificial foi criada para alcançar 0.

---

## 4. Testes de regressão

Novos testes em `tests/Run.Tests.ps1` (arquivo que também passa pelo scanner AST de somente leitura):

**Suíte J — FMP-01 (43 asserções):**

- **B0:** nota 100, `none_detected`, Inicialização `eligible:false/no_base_rules`, peso elegível 85, sem limite.
- **Estrutural:** categoria sem regra-base penalizável nunca é elegível; categoria elegível sempre tem ≥ 1 verificação coberta.
- **B1:** `critical`, nota ≤ 49, `uncappedScore` 86, `scoreCap` 49, `capped`, `status ok` com `confidence high` (dados confiáveis ≠ saúde), `riskReasons` com SMART e Unhealthy, dedução 12 (dedupe preservado).
- **Equivalência entre modos:** B1 em Simples e em Completa dá a mesma nota, o mesmo risco e o mesmo peso elegível.
- **B2:** dedução 61, nota 28, `critical`, limite não altera nota já inferior.
- **Cobertura parcial (SMART `access_denied`):** 100, `provisional`, `none_detected`, cobertura < 100.
- **SMART desconhecido + `Warning`:** `elevated`, 86 sem limite, `provisional`.
- **Categoria sem evidência:** armazenamento `no_evidence`, peso elegível 55, `provisional`.
- **Nota indisponível com falha comprovada:** `unavailable` + `critical`. Sem dados: `undetermined`.
- **Achados só da Completa** (`advanced-mixed`) não elevam o risco-base.
- **HTML:** `class="risk critical"` com o texto localizado, aviso do limite com 49/86, nota exibida 49, Inicialização "fora da nota", rótulo "Confiança dos dados", `class="risk none_detected"` em B0.

**Suíte K — FMP-04 (13 asserções):**

1. Análise **AST** de `Rules.ps1`: exatamente **34** textos canônicos em `Limitations`, todos com chave estável nos dois idiomas.
2. Análise **AST** dos 6 coletores: exatamente **22** chamadas a `Add-FmpLimitation`, todas resolvendo `limit.<LocaleKey|Key>` nos dois idiomas.
3. A nota tem 2 limitações, com 2 chaves válidas.
4. O JSON mantém o texto canônico com `limitationKeys` paralelo (`limited-access`).
5. Laudos PT-BR de 5 fixtures (`demo-synthetic`, `limited-access`, `advanced-mixed`, `low-disk`, `startup-full`): nenhum texto canônico em inglês (regras, coletores, nota), nenhuma chave técnica e nenhum placeholder `{n}` sem valor.
6. Chave desconhecida cai para o detalhe canônico, nunca para a chave.

**Suíte F (existente):** a paridade PT-BR/EN das 414 chaves continua verificada.

**Expectativas existentes atualizadas** (mudança legítima de resultado, com a derivação registrada no próprio teste):

| Fixture / teste | Antes | Depois | Derivação |
|---|---:|---:|---|
| `win10-outdated` (simple) | 94 | **90** | Eventos sem evidência → fora; `100·(60−6)/60` |
| `low-disk` | 82 | **49** (bruta 79) | SMART `PredictFailure` → `critical`; `100·(85−18)/85 = 78,8` |
| `cpu-ram-spike` | 92 | **91** | `100·(85−8)/85 = 90,6` |
| `events-mixed` | 84 | **81** | `100·(85−16)/85 = 81,2` |
| `demo-synthetic` (Run e Visual) | 82 | **79** | `100·(85−18)/85 = 78,8` |
| `Collector.Tests` E2E | esperava a chave `gpu_ram_uint32` no HTML | espera o texto localizado e **proíbe** a chave | requisito do FMP-04 |

**Prova de que os testes detectam regressão** (mutação aplicada só na cópia do scratchpad):
- removi a exclusão `no_base_rules`;
- removi uma entrada da tabela de chaves;
- desliguei a chave na renderização de limites de módulo.

Resultado: **6 falhas** (`B0: inicializacao fora da nota`, `HTML B1: categoria inicializacao fora da nota`, `regras: toda limitacao tem chave…`, `PT-BR demo-synthetic…`, `PT-BR limited-access…` e a suíte de coletores). Depois de restaurar o espelho, tudo voltou a verde.

**Sobre o TDD:**
- A suíte J foi executada antes da implementação e falhou pelo motivo esperado (`A propriedade 'riskLevel' não foi encontrada`).
- A suíte K não chegou a rodar nesse primeiro momento, porque a J abortou antes. O RED dela foi comprovado depois, pela mutação acima.

---

## 5. Resultados observados

Ambiente: Windows PowerShell **5.1.26100.9818**. PowerShell 7 não está instalado e **não foi validado**. Execução numa cópia espelhada (`robocopy /MIR`, sem `out` e `.playwright-mcp`). A pasta `out\` do workspace continuou vazia.

### 5.1 Suítes e validação

| Comando | Antes da correção | Depois |
|---|---|---|
| `tests\Run.Tests.ps1` | 194/194 | **254/254**, exit 0 (J = 43, K = 13; suíte D 62 → 66) |
| `tests\Collector.Tests.ps1` | 85/85 | **85/85**, exit 0 |
| `tests\Visual.Tests.ps1` | 193/193 | **193/193**, exit 0 |
| `fixmypc.ps1 -ValidateOnly` | PASS, 15 arquivos, 337 chaves | **PASS**, 15 arquivos, 0 violações, **414** chaves por idioma |

Segurança das suítes, confirmada antes de executar:
- `Run.Tests` só chama `fixmypc.ps1` com `-Fixture` ou `-ValidateOnly`. Os testes negativos usam o projeto-espelho com coletores `throw`.
- O harness de coletores substitui os cmdlets de sistema por sentinelas que lançam erro.
- A suíte visual não carrega coletores.

### 5.2 Cenários da auditoria (`docs/reviews/opus-5.5-evidence/Adversarial.Tests.ps1`, reexecutado)

| Cenário | Antes | Depois |
|---|---|---|
| **B0** saudável | 100 · ok · high · Inicialização 0/0 contando 15 pts | **100 · ok · high · risco `none_detected`** · Inicialização fora da nota · peso elegível 85 |
| **B1** disco com falha (Unhealthy + SMART + 12 erros de disco) | **88 · ok · high** · cobertura 100% | **49** (bruta 86) · `capped` · **risco `critical`** · status ok · confiança high (dados) · cobertura 100% |
| **B2** todas as regras-base em achado | 39 · ok | **28** · risco `critical` |
| **B7** pico de CPU de 4 s | 96 | 95 (FMP-07 continua aberto) |
| **B8** textos em inglês no laudo PT-BR | **7** | **0** |
| B3 (injeção), B4 (SIDs), B5 (ordem de severidade), B6 (`high_count`) | — | inalterados; fora do escopo e ainda abertos |

### 5.3 Amostras regeneradas

| Amostra | Nota · status · risco |
|---|---|
| `demo-report*.html` e JSON | 79 · ok · `elevated` · peso elegível 85 |
| `visual/provisional.*` (`limited-access`, simple) | 100 · provisional · `none_detected` |
| `visual/unavailable.*` (`degenerate`) | – · unavailable · `undetermined` |

### 5.4 Verificação de segurança do HTML gerado

Escopo: as 6 amostras + `b1-failing-disk.pt-BR.html` + `b3-injection.en.html`.

- 0 `<script>`, 0 atributos `on*` e 0 `src`/`href` externos.
- CSP idêntica à anterior (`default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`).
- Nenhuma chave técnica (`lim.*`, `limit.*`, `score.limitation.*`, `module.*`) visível.
- Todos os textos novos passam por `Get-FmpEsc`. O valor da classe `risk` só é emitido se pertencer a uma lista fechada (`critical`, `elevated`, `none_detected`, `undetermined`).
- Os `.ps1` alterados continuam ASCII. Os bytes não-ASCII encontrados em `Evidence.ps1` e nos testes já existiam e não vêm das minhas mudanças.

---

## 6. Limitações desta correção

- **Cobertura parcial dentro de uma categoria:** uma categoria com 1 de 5 verificações cobertas entra com peso integral. A cobertura por categoria é exibida e qualquer inconclusiva torna a nota provisória, mas o peso não é proporcional à cobertura (decisão consciente, para não introduzir uma nova heurística).
- **`Warning` não limita a nota:** só `Unhealthy` e `PredictFailure=true` são gatilhos críticos. `Warning` de disco ou volume dá risco `elevated`. Outros problemas graves (BSOD repetido, WHEA) também não limitam a nota, por serem históricos ou indiretos.
- **Valor do limite (49):** é uma escolha de política, justificada em §3 e configurável. Não é uma calibração estatística.
- **Arredondamento:** continua bancário (`[Math]::Round`), achado P3-02 da auditoria, fora do escopo.
- **Falha do módulo de inicialização** continua tornando a nota `unavailable` (regra preexistente), embora Inicialização não entre na nota. Mantido para não mudar contratos fora dos dois achados.
- **Rastreabilidade técnica mantida de propósito:** o id da regra na linha "Evidência" de cada achado, o JSON `measured` e os nomes de cmdlets na Metodologia continuam visíveis como trilha de auditoria. Não são chaves de tradução.
- **Exceções do sistema:** o texto bruto da exceção (por exemplo, no detalhe de `smart_unavailable`) fica só no JSON. O HTML mostra a frase localizada.
- **Verificação visual:** não houve verificação em navegador (responsividade 320–1440 px, impressão, leitores de tela) da nova linha "Risco diagnóstico" e dos novos avisos. As classes reaproveitam o layout de `facts` e `callout`, que é testado estruturalmente pela suíte visual.
- **Pendências:** PowerShell 7 e coletores reais em Windows 10/11 continuam sem validação.

---

## 7. Riscos residuais

- **Consumidores do JSON:** alguém que leia só `score` sem `riskLevel` ainda pode interpretar mal um laudo provisório. O schema agora exige `riskLevel` e o HTML o exibe ao lado da nota.
- **Mudança de nota entre versões:** quem comparar laudos antigos e novos verá notas diferentes para os mesmos dados (por exemplo, demo 82 → 79). O CHANGELOG registra isso. Não existe versão de algoritmo no JSON, porque `schemaVersion` foi mantido em 1.0.0. Recomenda-se decidir se isso merece um `scoreAlgorithmVersion`.
- **Textos canônicos novos:** um texto de limitação adicionado sem chave cai para o inglês. A suíte K falha nesse caso, pela contagem AST e pela varredura dos laudos PT-BR.
- **Achados ainda abertos que afetam a interpretação:**
  - FMP-05: severidades invertidas; o laudo ainda lista "<10% livre" antes de "<5% livre".
  - FMP-06: `startup.high_count`.
  - FMP-07: CPU de 4 s ainda penaliza.
  - FMP-08: SIDs no sanitizado.

---

## 8. Arquivos modificados

| Tipo | Arquivos |
|---|---|
| **Produção** | `src/analysis/HealthScore.ps1`, `src/analysis/Rules.ps1`, `src/analysis/Evidence.ps1`, `src/reports/HtmlRenderer.ps1`, `src/collectors/Events.ps1`, `src/collectors/Performance.ps1`, `src/collectors/Startup.ps1` |
| **Configuração e dados** | `rules/rules.json`, `locales/pt-BR.json`, `locales/en.json`, `templates/style.css`, `schemas/diagnostic.schema.json` |
| **Testes e fixtures** | `tests/Run.Tests.ps1`, `tests/Collector.Tests.ps1`, `tests/Visual.Tests.ps1`, `tests/fixtures/demo-synthetic.json` |
| **Amostras** | `samples/demo-report.html`, `samples/demo-report.en.html`, `samples/demo-diagnostic-sanitized.json`, `samples/demo-diagnostic-internal.json`, `samples/visual/provisional.pt-BR.html`, `samples/visual/provisional.en.html`, `samples/visual/unavailable.pt-BR.html`, `samples/visual/unavailable.en.html` |
| **Documentação** | `docs/methodology.md`, `README.md`, `README.pt-BR.md`, `CHANGELOG.md`, este arquivo |

**Não alterados:** `fixmypc.ps1` (consentimento e fluxo), `src/security/*` (política somente leitura e sanitização), `SKILL.md`, adaptadores e o relatório da auditoria final.

**Estado:** FMP-01 e FMP-04 corrigidos e verificados offline. A auditoria final **continua com achados abertos**: FMP-02, 03, 05, 06, 07, 08, 09, 10 e os P3.
