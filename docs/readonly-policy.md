# Política somente leitura do FIX MY PC

O FIX MY PC usa consultas locais e passivas para diagnóstico. A política veda elevação, reparos, instalação, remoção de software, alterações de registro, serviços, drivers, tarefas ou políticas e acesso à rede. Consultas que podem iniciar manutenção, como `Win32_Product` e pesquisa do Windows Update, ficam fora da coleta.

## Consentimento

O CLI exige uma confirmação interativa exata ou, em execução por agente, `-AcceptReadOnlyPolicy` acompanhado do `-ConsentToken` que `-Plan` imprimiu para exatamente aquela execução (2.0). `-Yes` usa as opções padrão sem conceder consentimento. Uma sessão sem entrada interativa e sem consentimento termina com código 3. Uma solicitação de fixture sempre segue o caminho sintético. Arquivos inválidos e valores vazios terminam com erro antes de carregar coletores ou criar saída.

### Limite do consentimento em execuções por agente (FMP-09)

`-AcceptReadOnlyPolicy` **não prova que um humano autorizou a coleta**. É uma declaração de quem monta a linha de comando: um agente que ignore as instruções pode incluí-la sem perguntar, e o script não consegue distinguir os dois casos. Por isso o consentimento deve ser pedido à pessoa **a cada execução real**, na conversa atual, mostrando o comando exato, o modo, o idioma e a pasta de saída. Um "sim" anterior (outra pasta, modo, idioma, máquina ou sessão) não vale. A flag não deve ser guardada em script, alias, gancho, tarefa agendada ou regra de permissão permanente.

Mecanismos de confirmação adicionais foram avaliados:

| Opção | Avaliação |
|---|---|
| Confirmação interativa digitada (já existe) | Prova humana apenas quando a pessoa executa o comando no próprio terminal. Recomendada. |
| Aprovação por comando do host do agente (Claude Code, Codex) | Único ponto em que uma pessoa é de fato consultada em fluxos de agente. Não criar regra "sempre permitir" para `fixmypc.ps1`. |
| Token de escopo impresso por `-Plan` (`-ConsentToken`, 2.0) | **Implementado.** `-Plan` não coleta nem grava nada; imprime o pedido de autorização (modo, idioma, objetivo, categorias de dados, duração estimada, pasta, processamento pela IA, ausência de reparos, comando exato) e um token `fmpc1-<emissão UTC>-<16 hex>` = SHA-256 truncado de modo, sintoma, idioma, janela, `-DuringProblem`, JSON interno e pasta. A execução real com `-AcceptReadOnlyPolicy` recusa (código 3) token ausente, malformado, de outro escopo, emitido no futuro ou com mais de 30 minutos. A pasta faz parte do escopo e precisa não existir. **Consumo único (Fase 0, C1):** antes de carregar qualquer coletor, a execução real cria a pasta com ACL privada e, dentro dela, `run-reservation.json` com criação exclusiva (`FileMode.CreateNew`); só a execução que cria esse arquivo coleta. Pasta já reservada, ou preexistente sem ACL protegida, termina com código 3 sem coleta. O arquivo nunca é apagado: após sucesso, falha, interrupção ou disputa simultânea, a mesma autorização não serve de novo. Ele contém só um identificador aleatório da execução e o horário UTC, nunca o token ou caminhos. **Limite:** o token não é segredo e não prova que um humano respondeu; qualquer processo com o mesmo shell pode rodar `-Plan`. Ele garante vínculo ao comando aprovado, validade curta e uso único; a prova humana continua sendo a resposta explícita no chat e, quando ativa, a aprovação por comando do host. |
| Token de consentimento emitido em execução interativa (`-IssueConsentToken`) | **Não implementado.** Um agente com acesso de shell ao mesmo usuário lê ou cria o arquivo do token; acrescenta estado persistente e complexidade sem provar que um humano respondeu. Reavaliar só se houver um canal fora do alcance do agente (por exemplo, confirmação do sistema operacional). |

O fluxo atual não foi enfraquecido: `-Yes` continua sem conceder consentimento e a coleta real continua exigindo a resposta interativa ou a flag com token válido. Em terminal interativo, uma flag sem token válido volta a perguntar ao humano em vez de prosseguir.

Use um processo sem perfil, com a política de execução efetiva da máquina. No teste offline desta revisão, o PowerShell 5.1 do ambiente exigiu `-ExecutionPolicy RemoteSigned` no processo de teste. A opção do processo é temporária e não prevalece sobre a política de grupo. Os adaptadores não pedem substituição de política.

## Verificação estática

O ponto de entrada e o scanner compõem a base de confiança inicial. O scanner analisa uma lista explícita de arquivos e recusa arquivos obrigatórios ausentes. A análise ocorre antes de carregar os módulos auxiliares. Os seis coletores só são carregados no ramo real, após consentimento e validação dos caminhos.

- Comandos externos, aliases, nomes qualificados, invocação dinâmica e parâmetros não listados são rejeitados. As funções internas precisam estar declaradas no código escaneado.
- O carregamento de módulos usa caminhos literais declarados. O invólucro do coletor executa um bloco de código literal do próprio projeto por um ponto específico.
- A verificação avalia redirecionamentos, gramática de importação, escopos de atribuição e chamadas .NET. A escrita de artefatos usa as operações de arquivo declaradas em Common.ps1.
- **Setters e métodos de instância (FMP-02).** O analisador acompanha, por função, o que cada variável local pode conter (união de todas as atribuições). Atribuições `a.b = x`, `a[k] = x`, `++`/`--` e métodos que alteram estado (`Add`, `Append`, `Clear`, `Remove`, `Replace`, `Sort`, `Stop`) só passam se o receptor for comprovadamente dado local: hashtable, `[ordered]`, `[pscustomobject]`, `List`, `StringBuilder`, `Stopwatch`, valores de tipo valor ou parâmetro tipado. Resultado de `Get-*`, variável de laço, parâmetro sem tipo e função desconhecida contam como "possível objeto vivo" e são recusados (`property_setter_not_allowed`, `index_setter_not_allowed`, `receiver_not_proven`). Atribuição membro-a-membro profunda (`a.b.c = x`) não é aceita; use `a['b']['c'] = x`. `Replace` e `Stop` não aceitam elementos de contêiner (por exemplo `FileInfo.Replace` é o único efeito colateral real alcançável).
- **Caminhos e consultas (FMP-03).** `Get-ChildItem`, `Get-Item`, `Get-ItemProperty`, `Get-Content` e `Test-Path` só aceitam literal autorizado (chaves de registro de uma lista fechada em `ReadOnlyPolicy.ps1`) ou, nos coletores, uma variável produzida por `Get-FmpCheckedPath` / `Get-FmpSafeRegistryPath`. UNC, caminhos de dispositivo (`\\?\`, `\\.\`), caminhos qualificados por provedor (`FileSystem::`, `Registry::`), arquivos sensíveis conhecidos e entrada de caminho por pipeline são recusados (`path_not_allowed`, `path_argument_not_proven`, `pipeline_path_input`). `Get-WinEvent` exige `-FilterHashtable` literal com chaves `LogName`, `ProviderName`, `Id`, `Level`, `StartTime`, `EndTime` e log `System`, `Application`, `Security` ou `Microsoft-Windows-Diagnostics-Performance/Operational` (2.0; sem `Path`). O método de leitura `ToXml()` do evento é permitido para ler campos pelo nome. `Get-CimInstance` exige `-ClassName` e `-Namespace` literais de listas fechadas e `-Filter` constante (`query_not_allowed`). A mesma lista de registro é aplicada em tempo de execução por `Get-FmpSafeRegistryPath`.
- **Limites desta análise.** É uma aproximação conservadora, não uma prova: não segue valores passados a funções internas nem objetos vivos guardados dentro de contêineres e depois lidos de volta. Funções internas que devolvem dados puros precisam ser declaradas em `$script:FmpDataFunctions`. Elementos de dicionários locais só são aceitos como receptores de `Add`, `Append`, `Clear`, `Remove` e `Sort`.
- O inventário do relatório lista comandos presentes no código de cada coletor. O inventário descreve caminhos possíveis de execução.
- **Fontes da observação (2.0).** As classes brutas `Win32_PerfRawData_PerfOS_Processor`, `Win32_PerfRawData_PerfOS_Memory`, `Win32_PerfRawData_PerfDisk_PhysicalDisk` e `Win32_PerfRawData_PerfProc_Process` entraram na lista fechada de classes CIM. São leituras de contadores; não há escrita, benchmark ou teste de estresse. O coletor limita janela (15-300 s), intervalo (1-30 s), leituras (61), discos (8), processos acompanhados (1000) e tempo total (janela + 45 s).
- **Exceção de hash do token de consentimento (2.0).** `src/common/Common.ps1` pode usar `[System.Security.Cryptography.SHA256]::Create().ComputeHash(...)` em memória para o token de escopo, como o renderizador já faz para o hash CSP. Não lê nem grava nada.
- **Exceção de hash do relatório (Etapa 10).** Somente arquivos com papel `writer` (`src/reports/`) podem usar `[System.Security.Cryptography.SHA256]::Create()`, `.ComputeHash(...)` sobre esse resultado e `[Convert]::ToBase64String`. É cálculo em memória do hash CSP do script estático de impressão; não lê nem grava nada.
- **Exceção da pasta de saída privada (Etapa 11, S11-01).** Somente `src/common/Common.ps1` pode montar em memória um `DirectorySecurity` protegido (`SetAccessRuleProtection`, `AddAccessRule`, `FileSystemAccessRule`, `WindowsIdentity::GetCurrent`, `SecurityIdentifier` de `LocalSystemSid`) e passá-lo a `[System.IO.Directory]::CreateDirectory(caminho, segurança)` em `New-FmpOutputDirectory`. A ACL só se aplica a pastas criadas pela execução; o CLI recusa pasta de saída existente, e `SetAccessControl` continua proibido em todo o código, então nenhuma ACL existente do computador é alterada.

### Garantias e limites do scanner

Garante, para o código escaneado: comandos e parâmetros fora da allowlist, comandos de reparo/escrita/rede/elevação conhecidos, invocação dinâmica, membros .NET não listados, setters sobre objetos não comprovadamente locais e caminhos/consultas fora das listas fechadas são recusados antes de qualquer coleta. Não garante: ausência de efeitos colaterais internos dos provedores do Windows (CIM/WMI, Event Log, Task Scheduler, autoload de módulos do sistema), integridade do PowerShell, do .NET ou dos módulos do Windows, comportamento de código fora da lista de arquivos escaneados, nem proteção contra quem já pode editar os arquivos do projeto. O scanner é uma barreira estática conservadora, não um sandbox.

A análise AST detecta mudanças fora do conjunto previsto. O resultado depende da integridade do código inicial, do shell, dos módulos do Windows e do ambiente de execução. A política não foi homologada contra efeitos indiretos dos provedores do Windows.

## Artefatos

Use um caminho absoluto em disco local com uma pasta nova para cada execução. O CLI rejeita caminhos UNC, unidades remotas, caminhos ambíguos, fluxos alternativos e pontos de nova análise no caminho. Valida os destinos antes da coleta e abre cada arquivo com criação exclusiva, que falha se o arquivo já existir. Uma falha de I/O durante a escrita pode deixar saída parcial. A pasta de saída precisa ser nova: o CLI recusa pasta existente e a cria com ACL protegida (só o usuário atual e SYSTEM, sem herança da pasta-mãe); os arquivos herdam essa ACL. Sem `-OutDir`, a saída vai para `%LOCALAPPDATA%\FixMyPC\fixmypc-<data>-<id>`; sem `%LOCALAPPDATA%` válido, o CLI falha com código 3. O CLI não lê nem altera ACLs existentes. Antes do consentimento ele avisa quando a unidade não é NTFS/ReFS (sem permissões) ou quando a pasta fica dentro do OneDrive. Administradores locais continuam com acesso. A verificação de pontos de nova análise é feita por caminho, com uma janela entre validação e abertura.

O padrão produz `report.html` e `diagnostic-sanitized.json`. O JSON interno exige `-IncludeInternalJson`. O HTML usa os mesmos dados sanitizados do JSON compartilhável. Revise o inventário restante antes de compartilhar.

## Operação offline

A auditoria Completa mantém metadados passivos de dispositivos, Defender, segurança, confiabilidade, hotfixes e programas. A validação Authenticode fica em `not_collected` enquanto não houver um mecanismo com verificação de certificados comprovadamente offline. Nenhum caminho de executável de inicialização é aberto para verificar assinaturas. Redirecionamentos da pasta de inicialização para rede ou links ficam fora da leitura.

## Ampliações da Fase A (mínimas e com teste negativo)

| Ampliação | Por que é necessária | Restrição aplicada pelo scanner |
|---|---|---|
| Chave ProviderName em Get-WinEvent | O ID sozinho é ambíguo: 153 existe em
vlddmkm e em disk | Só literais de uma lista fechada de 12 provedores, sem curinga, e sempre junto de LogName |
| Parâmetro -Oldest em Get-WinEvent | Saber até quando o log alcança, para não tratar falta de retenção como ausência de problema | Exige -MaxEvents 1 literal e filtro só com LogName |
| [TimeZoneInfo]::Local, IsInvalidTime, IsAmbiguousTime | Recusar ou sinalizar hora local afetada pelo horário de verão | Permitidos apenas em Common.ps1 |

Nenhuma classe CIM nova foi autorizada: as propriedades adicionais de memória e I/O pertencem a Win32_PerfRawData_PerfProc_Process, que já estava na lista. Não há Add-Type, WPR,
vidia-smi, linha de comando, caminho de executável ou assinatura digital. O horário do incidente e a tolerância fazem parte do escopo do token de consentimento.

## Ampliações das Fases B e C (validadas só por testes sintéticos)

| Ampliação | Por que é necessária | Restrição aplicada pelo scanner |
|---|---|---|
| Classes `MSFT_NetTCPConnection`, `MSFT_NetUDPEndpoint`, `MSFT_NetTCPSetting`, `MSFT_NetUDPSetting` e namespace `root\StandardCimv2` | Contar conexões por estado e processo e ler a faixa dinâmica | `-Property` obrigatório, literal e limitado: sem endereços nem portas de conexões |
| Classes `GPUEngine` e `GPUAdapterMemory` (contadores brutos) | Uso de motores e VRAM | `-Property` obrigatório, literal e limitado |
| Provedores `amdkmdag`, `amdkmdap`, `atikmdag`, `igfx`, `igfxn`, `Windows Error Reporting` | Eventos gráficos e relatórios de falha | Lista fechada de literais, sempre com `LogName` |
| `Get-StorageReliabilityCounter` | Contadores de confiabilidade, só em `-Depth deep` | Apenas `-PhysicalDisk` e `-ErrorAction` |

Não foram adicionados `Win32_Process`, leitura de `Report.wer`, despejos de memória, `netsh`, `nvidia-smi`, `Add-Type` nem elevação. A profundidade `deep` faz parte do escopo do token de consentimento.
