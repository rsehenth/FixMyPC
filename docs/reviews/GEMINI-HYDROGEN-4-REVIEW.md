# FIX MY PC — Revisão Técnica de Robustez, Compatibilidade e Integração Simulada

**Etapa 3 · 20 de novembro de 2026 · v0.1.0**  
**Responsável:** Gemini Hydrogen 4  
**Etapa anterior:** GPT Sol 6.2 (`APROVADO COM RESSALVAS`)

---

## 1. Resumo executivo

A Etapa 3 auditou os seis coletores PowerShell, os utilitários compartilhados, o pipeline de análise/pontuação, o renderizador HTML, a proteção de arquivos de saída e o comportamento sob `Set-StrictMode -Version 3.0` em PowerShell 5.1. Foi construído um harness de integração offline *fail-closed* (`tests/Collector.Tests.ps1`) baseado em `Runspace` isolado (`InitialSessionState::CreateDefault()` sem provedor `Registry`, com `PSModuleAutoLoadingPreference = 'None'`, remoção dos cmdlets reais de consulta e sentinelas de escape).

Todas as restrições absolutas de execução foram respeitadas: **nenhuma auditoria real foi executada**, `fixmypc.ps1` nunca foi invocado em modo de coleta real e `-AcceptReadOnlyPolicy` não foi usado para coleta.

---

## 2. Arquivos inspecionados e modificados

### Arquivos inspecionados
- Ponto de entrada e documentação: `fixmypc.ps1`, `SKILL.md`, `docs/readonly-policy.md`, `docs/methodology.md`, `docs/reviews/GPT-SOL-6.2-REVIEW.md`, `IMPLEMENTATION-REPORT.md`.
- Segurança, núcleo e análise: `src/security/ReadOnlyPolicy.ps1`, `src/security/Privacy.ps1`, `src/common/Common.ps1`, `src/analysis/Evidence.ps1`, `src/analysis/HealthScore.ps1`, `src/analysis/Rules.ps1`.
- Coletores: `src/collectors/System.ps1`, `src/collectors/Storage.ps1`, `src/collectors/Startup.ps1`, `src/collectors/Performance.ps1`, `src/collectors/Events.ps1`, `src/collectors/Advanced.ps1`.
- Apresentação, esquema e testes: `src/reports/HtmlRenderer.ps1`, `schemas/diagnostic.schema.json`, `rules/rules.json`, `locales/pt-BR.json`, `locales/en.json`, `tests/Run.Tests.ps1`, `tests/fixtures/*.json`.

### Arquivos modificados e criados
- `src/common/Common.ps1`: utilitários compartilhados (`Get-FmpSystemDrive`, `Test-FmpIsWow64Process`, `Get-FmpCleanString`, `ConvertTo-FmpNullableDouble`, `ConvertTo-FmpNullableInt`, `Get-FmpParsedDate`), proteção contra `NaN`/`Infinity` em `ConvertTo-FmpSerializable`, retorno do caminho normalizado em `Assert-FmpOutputPath` e revalidação pós-criação em `New-FmpOutputDirectory`.
- `src/security/ReadOnlyPolicy.ps1`: adição dos membros estáticos somente leitura `[Environment]::Is64BitOperatingSystem`, `[Environment]::Is64BitProcess`, `[int]::TryParse`, `[DateTime]::ParseExact`, `[DateTime]::TryParseExact` em `$script:FmpStaticMembers`.
- `src/analysis/Evidence.ps1`: correção de `limits` (`List[string]` -> `List[object]`) e adição de `Resolve-FmpCollectorErrorState`.
- `src/collectors/System.ps1`, `Storage.ps1`, `Startup.ps1`, `Performance.ps1`, `Events.ps1`, `Advanced.ps1`: endurecimento de contratos, tratamento StrictMode-safe, timeouts CIM (`-OperationTimeoutSec 15`), classificação de erros, deduplicação, correspondência passiva volume-disco e suporte a casos extremos.
- `src/analysis/Rules.ps1`: remoção de `Get-FmpParsedDate` duplicada (agora em `Common.ps1`), trim em `Caption`/`DisplayVersion` para `os.w10_eol`, fallback de `label` em `storage.disk_health_unhealthy` e tratamento de `startup.*` `unsupported` como `unknown` em `startup.high_count`.
- `src/reports/HtmlRenderer.ps1`, `locales/pt-BR.json`, `locales/en.json`, `fixmypc.ps1`: extração de `Get-FmpHtmlReportText` e pré-validação de todos os artefatos (`<= 8 MiB`) antes da criação do diretório e escrita em disco; correção de rótulo duplicado de versão/build no hardware (`report.hardware.os.build`); marcador `+` em logs de eventos truncados; formatação de data em registros de confiabilidade; guarda numérica em `pagefile` e `intervalSec`; fallback quando `cpu` é nulo.
- `tests/Collector.Tests.ps1` (novo): harness offline *fail-closed* e 85 asserções para os 6 coletores, pipeline integrado e teste de volume.
- `tests/Run.Tests.ps1`: expansão de 181 para 193 asserções (segurança de caminhos, `NaN`/`Infinity`, regressões Win10/HTML/startup, limite de 8 MiB e execução integrada de `Collector.Tests.ps1`).
- `docs/homologation-plan.md` (novo): plano de homologação futura em ambientes Windows 10/11 autorizados (não executado).
- `docs/reviews/GEMINI-HYDROGEN-4-REVIEW.md` (novo): este relatório.

---

## 3. Defeitos encontrados e correções realizadas

| Severidade | Componente | Defeito identificado | Correção aplicada |
|---|---|---|---|
| **P0/P1** | `Evidence.ps1` | `New-FmpCollectorContext` inicializava `limits` como `List[string]`; cada `OrderedDictionary` passado por `Add-FmpLimitation` era convertido na string literal `"System.Collections.Specialized.OrderedDictionary"`, quebrando JSON e HTML de limitações em toda coleta real. | Alterado para `List[object]`. |
| **P1** | `System.ps1`, `Storage.ps1`, `Startup.ps1`, `Performance.ps1`, `Events.ps1`, `Advanced.ps1` | Acessos diretos a propriedades (`$os.LastBootUpTime`, `$cv.UBR`, `$s.Reason`, `$d.Size`, `$a.Execute`, `$e.TimeCreated`, etc.) quebravam sob `Set-StrictMode -Version 3.0` quando objetos CIM/registro chegavam parciais ou malformados, ou convertiam `$null` em `0` / `$false`. | Substituídos por `Get-FmpValue`, `Get-FmpCleanString`, `ConvertTo-FmpNullableInt` e `ConvertTo-FmpNullableDouble`, mantendo ausências como `$null` e degradando subchecks para `unknown`. |
| **P1** | `Storage.ps1` | (1) `Get-Volume` em partições sem letra retorna `[char]0`, gerando chave inválida; (2) volumes `Fixed` sem letra com saúde `Warning`/`Unhealthy` eram ignorados; (3) falhas de `Get-Volume`/`Get-PhysicalDisk` sempre viravam `unsupported` mesmo em `UnauthorizedAccessException`; (4) `Where-Object` sem `@()` externo falhava em `.Count` com 1 item sob StrictMode; (5) ausência de correspondência volume↔disco físico. | Tratamento de `[char]0` e captura passiva de volumes `Fixed` sem letra; classificação com `Resolve-FmpCollectorErrorState`; encapsulamento `@(...)`; associação passiva via `Win32_DiskDriveToDiskPartition` + `Win32_LogicalDiskToPartition` com degradação graciosa. |
| **P1** | `Startup.ps1` | Pastas Startup redirecionadas para rede (`\\...`) ou contendo junctions/reparse points faziam `Get-FmpCheckedPath` lançar exceção tratada como `error` do módulo; ações COM (`MSFT_TaskComHandlerAction`) sem `Execute` falhavam; `DelayedAutoStart = $null` virava `$false`; PS 32-bit em SO 64-bit lia `WOW6432Node` em duplicidade. | Detecção passiva de rede/reparse com `Add-FmpLimitation` e estado `unknown`; leitura segura de ações COM; preservação de `delayed = $null`; guarda `Test-FmpIsWow64Process` + deduplicação de caminhos Startup iguais. |
| **P1** | `Performance.ps1` & `HtmlRenderer.ps1` | `topProcessesByMemory` e `topProcessesByCpu` não emitiam `id`/`idProcess`, deixando a coluna de PID vazia no HTML; contadores de CPU fora de `[0..100]` ou processos encerrados no `Sort-Object` podiam corromper médias ou lançar exceção; `logicalProcessors` não era registrado em `performance.cpu`. | Inclusão de `id` e `idProcess`, filtro antes da ordenação, validação de faixa `[0..100]`, registro de `logicalProcessors` e `normalizedPercent`, e soma segura de múltiplos pagefiles. |
| **P1** | `Events.ps1` & `HtmlRenderer.ps1` | `Security` 4625 assumia ordenação fixa `[0]`/`[-1]` para `lastSeen`/`firstSeen`; eventos duplicados por `RecordId` não eram deduplicados; logs truncados eram impressos no HTML sem marcador `+`; registros de confiabilidade não passavam por `Get-FmpShortDate`. | Cálculo por min/max de `TimeCreated`, deduplicação por `RecordId`, marcador `+` no HTML quando `truncated = true`, formatação de data no RAC e verificação explícita de ausência do campo `Message`. |
| **P1** | `Advanced.ps1` | `IsSigned = $null` virava `$false` ("não assinado"); `PendingFileRenameOperations = @('')` gerava falso positivo de reinício pendente; `Get-HotFix` ordenava datas em string lexicograficamente (`12/01/2025` > `01/15/2026`); falha em um caminho de `Uninstall` descartava apps dos demais; lookup de drivers era O(P×D). | Preservação de `signed = $null`, filtro de strings vazias em renomeação pendente, `ConvertTo-FmpHotfixDate` cronológico, `try/catch` isolado por escopo de registro e indexação O(D) por `DeviceID`. |
| **P1** | `Rules.ps1`, `Common.ps1`, `HtmlRenderer.ps1`, `fixmypc.ps1` | `Caption` com espaço final (`"Microsoft Windows 10 Pro "`) falhava em `os.w10_eol`; `[double]::NaN`/`Infinity` quebravam serialização JSON estrita; `pagefile` nulo no HTML imprimia `0 B` ou quebrava em string; `fixmypc.ps1` gravava JSON antes de renderizar/validar o HTML (risco de saída parcial se HTML excedesse 8 MiB). | `.Trim()` em `Caption`/`DisplayVersion`, conversão de `NaN`/`Infinity` para `$null`, guarda numérica em `pagefile`/`intervalSec`, e pré-geração + checagem `<= 8 MiB` de todos os artefatos antes de criar o diretório. |

---

## 4. Mocks, fixtures e testes executados

### Harness offline (`tests/Collector.Tests.ps1`)
- **Prova de isolamento *fail-closed*:** Runspace via `InitialSessionState::CreateDefault()` com `PSModuleAutoLoadingPreference = 'None'`, remoção do provedor `Registry` (e `Certificate`/`WSMan`), remoção dos cmdlets reais de consulta (`Get-CimInstance`, `Get-WinEvent`, `Get-Process`, `Get-Volume`, `Get-PhysicalDisk`, `Get-ScheduledTask`, `Get-MpComputerStatus`, `Get-HotFix`, `Get-ItemProperty`, `Get-Item`, `Get-ChildItem`, `Test-Path`, `Start-Sleep`, `Get-Date`, `Get-Service`, `Get-WmiObject`, `Get-Counter`, `Get-AuthenticodeSignature`, `Import-Module`, `Get-Module`), limpeza de `Applications`/`Scripts` e injeção de sentinelas de escape que abortam o teste se qualquer cmdlet não declarado em `MissingCmdlets` for chamado.
- **Cobertura de cenários simulados:** Win10 e Win11, objetos CIM/registro malformados, números inválidos, arrays vazios e unitários, `UnauthorizedAccessException` (`access_denied`), `CommandNotFoundException` e `InvalidClass` (`unsupported`), timeouts simulados, dados duplicados (`RecordId`, WOW64, pastas Startup duplicadas), truncamento de logs, deslocamentos de fuso horário, pipeline E2E de 6 coletores (equivalência Simples vs. Completa) e teste de volume com 4.000 eventos sintéticos (`1.398.987` bytes em `3.390 ms`, abaixo do teto de `8 MiB`).

### Resultados observados após a última edição
- `tests\Collector.Tests.ps1` (PS 5.1.26100.9818): **85/85 asserções aprovadas, 0 falhas**.
- `tests\Run.Tests.ps1` (PS 5.1.26100.9818): **193/193 asserções aprovadas, 0 falhas** (inclui a execução integrada de `Collector.Tests.ps1`).
- `fixmypc.ps1 -ValidateOnly`: **PASS** (`15 arquivos analisados, nenhuma violação`, `296` chaves em `pt-BR` e `296` chaves em `en`, `rules.json: OK`).
- **PowerShell 7 (`pwsh`):** não instalado neste ambiente (`Test-Path` negativo em caminhos padrão e ausente no `PATH`). A compatibilidade com PS 7 foi preservada no código e na análise estática, porém **não foi executada nesta etapa**.

---

## 5. Segurança dos arquivos de saída e confiabilidade de diagnósticos

- **Validação de caminhos:** Testes cobriram travessia (`..\`), caminhos relativos, UNC (`\\...`), caminhos de dispositivo (`\\.\PhysicalDrive0`, `\\?\C:\...`), fluxos alternativos (`:stream`), pontos/espaços finais (`dir.`, `file.txt `), nomes reservados (`CON`, `NUL.txt`), escrita exclusiva (`CreateNew` + `FileShare.None`), contenção contra escrita concorrente e bloqueio pré-gravação acima de `8 MiB`.
- **Risco residual (TOCTOU):** Em .NET Framework / PowerShell 5.1 sem P/Invoke nativo (`openat` / `FILE_FLAG_OPEN_REPARSE_POINT`), a revalidação após `CreateDirectory` e imediatamente antes de `File.Open` reduz a janela, mas não elimina 100% uma substituição concorrente do diretório por processo com escrita no diretório pai. O modelo de ameaça pressupõe diretório de saída privado com ACL restrita ao usuário.
- **Confiabilidade:** Nenhum erro de coletor, campo ausente, `access_denied`, `unsupported` ou amostra incompleta é convertido em `pass`; `Authenticode` e pesquisa ativa do `Windows Update` permanecem em `not_collected`.

---

## 6. Coletores ainda não homologados e restrições respeitadas

- Todos os seis coletores (`System`, `Storage`, `Startup`, `Performance`, `Events`, `Advanced`) foram validados **exclusivamente com provedores simulados**. Permanecem **não homologados em Windows real** até a execução autorizada de `docs/homologation-plan.md`.
- Restrições respeitadas: zero consultas reais a eventos, processos, serviços, registro, drivers, SMART ou inventário do anfitrião; zero elevação, benchmarks reais, junctions reais no host, instalações, VMs ou commits/push.

---

## 7. Recomendações para Sonnet 5.5

1. Integrar os assets oficiais em `assets/branding/` e `assets/report/` preservando HTML offline, CSP (`default-src 'none'`), ausência de JavaScript e limite de `8 MiB` por artefato (atenção ao tamanho dos PNGs caso embutidos em Base64 — redimensionar/otimizar para manter `report.html <= 8 MiB`).
2. Manter intacta a separação coleta × análise × apresentação e todas as 296+ chaves de idioma em `pt-BR` e `en`.
3. Antes da publicação, executar `docs/homologation-plan.md` em VMs Windows 10/11 autorizadas (e em PowerShell 7) e revisar a tabela estática `windowsLifecycle` em `rules/rules.json`.

---

**Classificação final:** **APROVADO PARA PRÓXIMA ETAPA**  
*(Aprovação restrita à continuidade do desenvolvimento/UI na Etapa 4; não autoriza auditoria real no anfitrião nem publicação sem homologação Windows autorizada e validação em PowerShell 7.)*
