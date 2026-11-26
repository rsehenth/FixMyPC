# Plano de Homologação Futura em Ambientes Windows Autorizados

**Projeto:** FIX MY PC: PC Diagnostic & Audit Skill (`v0.1.0`)  
**Status:** **PREPARADO — NÃO EXECUTADO NA ETAPA 3**  
**Pré-requisito de execução:** Autorização explícita do proprietário da máquina/VM de teste e consentimento específico por execução.

---

## 1. Objetivo

Validar os seis coletores (`System`, `Storage`, `Startup`, `Performance`, `Events`, `Advanced`), os artefatos gerados e a política somente leitura em ambientes Windows 10 e 11 reais ou em VMs autorizadas, sem alterar o sistema operacional, sem tráfego de rede e com medição objetiva de duração e consumo de recursos.

---

## 2. Pré-condições

1. Máquina física ou VM descartável/snapshotada dedicada e **explicitamente autorizada** para o teste.
2. Snapshot/ponto de restauração prévio criado (quando em VM) para comparação pós-execução.
3. Execução prévia bem-sucedida de:
   - `powershell -NoProfile -NonInteractive -File fixmypc.ps1 -ValidateOnly` (exit `0`, 0 violações AST).
   - `powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\Run.Tests.ps1` (todos os testes offline aprovados).
4. Diretório de saída absoluto, local, novo e com ACL restrita ao usuário da sessão (ex.: `C:\Users\<tester>\fmp-homolog\run-01`).
5. Monitoramento externo de recursos e rede ativo (ex.: observador externo de I/O, CPU e conexões de rede — nunca alterar o FIX MY PC para coletar telemetria externa).

---

## 3. Comandos permitidos e consentimento necessário

A execução deve usar **exclusivamente** o ponto de entrada `fixmypc.ps1`:

- **Sessão interativa (consentimento humano digitado):**
  ```powershell
  powershell -NoProfile -File fixmypc.ps1 -Mode simple -Language pt-BR -OutDir "<dir>"
  powershell -NoProfile -File fixmypc.ps1 -Mode full -Language en -OutDir "<dir>"
  ```
- **Sessão não interativa (somente após consentimento explícito para aquela execução específica):**
  ```powershell
  powershell -NoProfile -NonInteractive -File fixmypc.ps1 -Mode simple -Language pt-BR -OutDir "<dir>" -AcceptReadOnlyPolicy
  powershell -NoProfile -NonInteractive -File fixmypc.ps1 -Mode full -Language en -OutDir "<dir>" -AcceptReadOnlyPolicy
  ```
- **Elevação (Administrador):** **Proibida por padrão.** Cenários marcados como *Administrador* exigem autorização separada e explícita para aquela execução específica.
- **Comandos proibidos:** qualquer invocação direta de `src\collectors\*.ps1`, `Win32_Product`, `chkdsk`, `sfc`, `dism`, `powercfg`, alteração de registro/serviços/tarefas ou uso de `-ExecutionPolicy Bypass` persistente.

---

## 4. Dados coletados e limites previstos

| Modo | Dados coletados | Dados explicitamente excluídos | Limites operacionais |
|---|---|---|---|
| `simple` | Metadados de SO/build/CPU/RAM/GPU/discos/volumes; eventos `System` e `Application` (Error/Critical, 7 dias); chaves Run/RunOnce 64/32 bits, pastas Startup, tarefas de logon, serviços automáticos; 3 amostras de CPU + RAM/commit/pagefile/top processos; volumes + `Get-PhysicalDisk` + SMART `PredictFailure`. | Mensagens brutas de eventos, argumentos de processos, números de série, chaves de produto, GUIDs de máquina, destinos de `.lnk`, pastas Startup em rede/reparse. | `Get-CimInstance -OperationTimeoutSec 15`; eventos máx. `2.000`/log e `40` grupos; startup máx. `300` itens / `100` tarefas; CPU `3×2 s`; artefatos `<= 8 MiB`. |
| `full` | Todos os de `simple`, mais RAC (`Win32_Reliability*`), Security 4625 (máx. 500), dispositivos com código de erro (`<= 50`), drivers de dispositivos com erro (`<= 10` dispositivos), Defender (`Get-MpComputerStatus`), SecurityCenter2 (`AntiVirusProduct`), indicadores de reinício pendente, hotfixes (top 5), apps em `Uninstall` (máx. 300). | Pesquisa Windows Update COM (`not_collected`), verificação Authenticode (`not_collected`), `Win32_Product`. | Duração-alvo (não homologada): Simples `~<= 2 min`, Completa `~<= 5 min`. |

---

## 5. Matriz de cenários de homologação

| ID | Ambiente / Condição | Privilégio | Modo | O que verificar e evidência de sucesso |
|---|---|---|---|---|
| H-01 | Windows 10 (Home/Pro 22H2, edição PT-BR e EN) | Usuário padrão | `simple` e `full` | `Caption` reconhecida mesmo com espaços extras; `os.w10_eol` avaliada corretamente; pontuação base equivalente entre `simple` e `full`; `events.security` = `access_denied` sem penalidade; `score.status` honesto. |
| H-02 | Windows 11 (23H2/24H2/25H2) | Usuário padrão | `simple` e `full` | `DisplayVersion` e `UBR` corretos; `os.w10_eol` = `pass`; processos em `topProcessesByMemory` e `topProcessesByCpu` exibem PIDs no HTML; zero chaves de idioma ausentes. |
| H-03 | Sessão com privilégio elevado (mediante autorização separada) | Administrador | `full` | Eventos `Security` (4625) e SMART WMI (`MSStorageDriver_FailurePredictStatus`) retornam dados ou estado `empty` válido sem `access_denied`; comparar nota-base com H-01/H-02 para confirmar não interferência do modo `full`. |
| H-04 | Computador com SSD SATA | Padrão / Admin | `simple` | `physicalDisks` identifica `MediaType = SSD`, `BusType = SATA`; correspondência `physicalDiskIndices` vincula volume do sistema ao disco físico esperado; SMART tratado sem falso positivo. |
| H-05 | Computador com NVMe | Padrão / Admin | `simple` | `physicalDisks` identifica `BusType = NVMe` (e `Win32_DiskDrive` tratado corretamente); temperaturas/atributos proprietários não quebram coleta. |
| H-06 | Máquina Virtual (Hyper-V / VirtualBox / VMware) | Padrão | `simple` e `full` | Discos virtuais tratados sem erro; ausência de SMART (`unsupported`/`empty`) nunca gera estado `pass` em `storage.smart_predict_failure`; GPU virtual sem `VRAM` exata mantém limitação `gpu_ram_uint32`. |
| H-07 | Microsoft Defender ativo vs. desabilitado / substituído por AV de 3º | Padrão | `full` | Com Defender ativo -> `pass`; com Defender desabilitado e sem AV 3º -> `finding` (`security.defender_disabled`); com AV 3º registrado em `SecurityCenter2` -> `security.third_party_av` informativo e `defender_disabled` = `unknown` (nunca atesta proteção ativa). |
| H-08 | Provedores RAC (`Win32_Reliability*`) e SMART ausentes/desabilitados | Padrão | `full` | `events.reliability.status` = `unsupported` (não `error` fatal nem prova estabilidade); `storage.smart.status` = `unsupported` ou `access_denied` -> `storage.smart_predict_failure` inconclusivo. |
| H-09 | Problemas simulados de permissões (ACL restrita em chave de registro/pasta Startup/log) | Usuário padrão | `simple` e `full` | Subchecks individuais degradam para `access_denied` ou `unknown` com limitação registrada; demais subchecks continuam funcionando; módulo não inventa estados `pass`. |
| H-10 | PowerShell 5.1 e PowerShell 7 (`pwsh`) + processos 32 bits (`WOW64`) | Padrão | `simple` e `full` | Saídas idênticas em esquema Draft-07; processo 32 bits registra limitação `wow64_32bit_process` sem duplicar itens `WOW6432Node`. |
| H-11 | Monitoramento de recursos e efeitos indiretos | Padrão | `simple` e `full` | Medir tempo total, pico de memória do processo PowerShell, I/O em disco e ausência de conexões de rede de saída durante a coleta; confirmar HTML e JSONs `<= 8 MiB`. |

---

## 6. Critérios de interrupção (Abort)

Interromper imediatamente a execução de homologação caso ocorra qualquer um dos eventos abaixo:

1. Falha no gate AST (`exit 2`).
2. Qualquer tráfego de rede originado pelo processo PowerShell durante a coleta.
3. Uso sustentado de CPU > 50% pelo coletor fora da janela de 6 s ou duração > 2 min (`simple`) / > 5 min (`full`) sem justificativa de hardware lento.
4. Crescimento descontrolado de memória (> 512 MB no processo do coletor) ou travamento > 30 s em uma única consulta CIM/WinEvent.
5. Qualquer tentativa de escrita fora do diretório `-OutDir` autorizado.

---

## 7. Como confirmar que não houve modificação no Windows

Antes e após o teste em VM/máquina autorizada:

1. Comparar snapshot da VM ou capturar estado antes/depois de:
   - Serviços (`Get-Service` / hash da lista de serviços e `StartType`).
   - Chaves `Run`/`RunOnce` e tarefas agendadas.
   - Arquivos em `%TEMP%`, `%LOCALAPPDATA%` e pasta do usuário (apenas `-OutDir` deve conter os 2 ou 3 artefatos gerados).
2. Verificar logs de auditoria/Process Monitor (ProcMon) filtrando pelo PID do `powershell.exe`/`pwsh.exe`: confirmar ausência de operações `RegSetValue`, `RegCreateKey`, `WriteFile` fora de `-OutDir` (e cache normal do runtime .NET/PS) e ausência de pacotes `TCP/UDP Send`.
3. Validar que nenhum arquivo de configuração ou política de execução persistente do sistema foi alterado (`Get-ExecutionPolicy -List`).

---

## 8. Riscos residuais documentados

1. **Janela TOCTOU em saída compartilhada:** A validação de reparse points em `Common.ps1` reduz a janela antes da abertura exclusiva (`FileMode.CreateNew`, `FileShare.None`), mas em .NET Framework 4.x / PowerShell 5.1 sem P/Invoke nativo existe uma janela sub-milissegundo caso outro processo com escrita no diretório pai substitua a pasta por uma junction durante a escrita. Mitigação: usar `-OutDir` privado com ACL restrita ao usuário.
2. **Efeitos indiretos de provedores Windows:** A conformidade AST garante o conjunto de comandos do FIX MY PC, mas não controla efeitos internos de provedores WMI/CIM de terceiros ou do próprio SO (por isso o monitoramento em H-11 é obrigatório).
3. **Retrato estático de ciclo de vida (`rules.json`):** As datas de fim de suporte (Home/Pro) dependem de atualização manual futura antes de publicação.
