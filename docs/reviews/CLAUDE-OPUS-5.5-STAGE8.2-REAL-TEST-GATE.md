# FIX MY PC — Gate final para o primeiro teste real supervisionado

- **Executado por:** Claude Opus 5.5 (pedido endereçado a "GPT Sol 6.2")
- **Data:** 2026-11-21
- **Base:** [Etapa 8.1](SONNET-5.5-STAGE8.1-BLOCKER-FIX.md) · [Revisão independente Etapa 8](GPT-SOL-6.2-POST-V2-INDEPENDENT-REVIEW.md)
- **Veredito:** **APTO PARA SOLICITAR AUTORIZAÇÃO DE TESTE REAL**

Nenhuma coleta real foi feita. `-AcceptReadOnlyPolicy` não foi usado, nenhum coletor real foi consultado e nenhum código de produção foi alterado.

## 1. Correções confirmadas

| # | Verificação | Resultado |
|---|---|---|
| 1 | `OneSyncSvc_1a2b3` / `Sync Host_1a2b3` via CLI `-Fixture -Mode full` (pt-BR e en) | **Confirmada.** JSON sanitizado: `OneSyncSvc_<LUID>` / `Sync Host_<LUID>`. Ocorrências de `1a2b3`: 0 no JSON, 0 no HTML (`Sync Host_&lt;LUID&gt;` 2x). |
| 2 | 150 apps (`truncated=false`) | **Confirmada.** `totalCount=150`, `items=150`, `truncated=false`, `sanitizedTruncated=false`, `privacy.truncated=false`, sem aviso no HTML. |
| 2 | 151 apps (`truncated=false`) | **Confirmada.** `totalCount=151`, `items=150`, `presentedCount=150`, `truncated=true`, `collectionTruncated=false`, `sanitizedTruncated=true`, `privacy.truncatedCollections=[advanced.installedApps.items 151→150]`. HTML pt-BR: "Visão sanitizada limitada a 150 de 151 item(ns)…"; en: "Sanitized view capped at 150 of 151…". HTML sem `<script>`, sem `on*=` e sem URLs externas. |
| 3 | Scanner AST (só parse, nunca executado, `-Role collector`) | **Confirmada.** Rejeitados com `receiver_not_proven`: X16 exato, membro ausente, parâmetro `[IDictionary]`, índice não comprovado, `[pscustomobject]`, `ConvertTo-FmpSerializable`, membro desconhecido de contexto e **4 variantes novas**: reatribuição da variável, sobrescrita do campo (`$d.items = Get-Process`), sobrescrita por índice (`$d['items'] = …`) e variável de laço sobre objetos vivos. Controles aceitos: dicionário local `Add/Remove`, G16 e G17. |
| 5 | Consentimento | **Intacto.** Execução real sem a flag (`-NonInteractive`): `exit 3`, pasta não criada. Com `-Yes` e sem a flag: `exit 3`, pasta não criada. O consentimento (linha 164) é verificado antes do carregamento dos coletores (linha 218). |
| 5 | Caminhos de saída | **Intactos.** Pasta com artefatos, caminho relativo, UNC e raiz do drive: `exit 3`. A pasta só é criada depois da análise (`New-FmpOutputDirectory`, linha 297), então um Ctrl+C durante a coleta não deixa arquivos. |

## 2. Testes e códigos de saída (Windows PowerShell 5.1)

| Comando | Resultado | Exit |
|---|---|---:|
| `fixmypc.ps1 -ValidateOnly` | PASS: 15 arquivos, 0 violações, 422 chaves por idioma, `rules.json` OK | 0 |
| `tests/Collector.Tests.ps1` | 85/85 | 0 |
| `tests/Visual.Tests.ps1` | 290/290 | 0 |
| `tests/Run.Tests.ps1` | 423/423 (111 s) | 0 |
| CLI fixture 150 pt-BR / 151 pt-BR / 151 en | artefatos gerados | 0 / 0 / 0 |
| 6 casos negativos de consentimento e caminho | rejeitados | 3 (todos) |

## 3. Riscos residuais para o primeiro uso

1. **Sem watchdog global.** As consultas CIM têm `-OperationTimeoutSec 15`, mas `Get-WinEvent` (7 dias, até 2000 eventos por log) e `Get-ScheduledTask` não têm limite de tempo. A supervisão manual cobre isso (ver §5).
2. **A sanitização é baseada em padrões.** Formatos reais de identificadores ainda não vistos podem passar. O JSON sanitizado deve ser revisado antes de ser compartilhado.
3. **Dados reais nunca foram processados.** Toda a validação usou fixtures e mocks; este primeiro uso é a verificação disso.
4. **Sem administrador**, alguns checks terão `access_denied`/`partial` e a cobertura da nota será menor. É o esperado e não é motivo para interromper.
5. **PowerShell 7 não validado.** Use o Windows PowerShell 5.1 (`powershell.exe`).
6. P3: `Run.Tests.ps1` deixa `out\fmp-tests-<guid>\` no repositório (o resíduo desta execução foi removido). Não bloqueia.

## 4. Procedimento supervisionado (modo Simples, sem administrador)

1. Abra uma janela **normal** do Windows PowerShell (não "Executar como administrador") e confirme que o resultado é `False`:

   ```powershell
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

2. Execute o comando abaixo. A pasta de saída é nova, fica no perfil do usuário (privada por herança de ACL) e fora do repositório. O consentimento é dado **interativamente**, digitando `sim`, sem `-AcceptReadOnlyPolicy`. `-ExecutionPolicy` vale só para esse processo:

   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File <workspace>\fixmypc.ps1 -Mode simple -Language pt-BR -OutDir "$env:LOCALAPPDATA\FixMyPC\auditoria-$(Get-Date -Format yyyyMMdd-HHmmss)"
   ```

3. Leia a política mostrada e responda `sim` no prompt de consentimento.
4. Acompanhe as linhas de progresso por módulo (`system`, `events`, `startup`, `performance`, `storage`) e o processo no Gerenciador de Tarefas.
5. Ao final, confirme que a pasta contém **apenas** `report.html` e `diagnostic-sanitized.json` e procure identificadores antes de compartilhar qualquer coisa:

   ```powershell
   $o = Get-ChildItem "$env:LOCALAPPDATA\FixMyPC" -Directory | Sort-Object CreationTime | Select-Object -Last 1; Get-ChildItem $o.FullName; Select-String -Path "$($o.FullName)\*" -Pattern $env:COMPUTERNAME, $env:USERNAME -SimpleMatch | Measure-Object
   ```

## 5. Condições de interrupção (Ctrl+C e não reexecutar sem nova análise)

- **Lentidão:** um módulo sem nova linha de progresso por mais de **3 min**, ou execução total acima de **10 min**.
- **CPU:** o processo `powershell` acima de **50% da CPU total por mais de 2 min**, ou o sistema deixa de responder.
- **Memória:** working set acima de **1,5 GB**, ou crescendo continuamente sem estabilizar.
- **Comportamento inesperado:** prompt de UAC, pedido de credenciais, janela aberta, qualquer pergunta além do consentimento, alerta de antivírus/EDR, ou mensagem de escrita fora da pasta de saída.
- **Falha de provedor:** `exit 4` (`ERROR:`) encerra e o console é guardado. Um módulo `partial`/`access_denied` isolado **não** é motivo para parar. **Dois ou mais módulos `failed`** pedem análise antes de outra execução.
- **Saída:** qualquer arquivo além dos dois esperados, ou `Select-String` encontrando o nome do computador ou do usuário, é bloqueador: não compartilhe e abra uma correção.
