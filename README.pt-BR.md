# FIX MY PC

[English](README.md) · **Português (Brasil)**

> **Status: Em desenvolvimento — Versão funcional de prévia.**
> Gratuito para uso não comercial sob a [PolyForm Noncommercial License 1.0.0](LICENSE).
> Código disponível (*source-available*), não é código aberto aprovado pela OSI. Nenhuma versão pública foi aprovada ainda.

O FIX MY PC é uma ferramenta de diagnóstico para Windows, somente leitura. Ela
executa verificações locais reais, aplica um conjunto determinístico de regras e
gera um relatório HTML offline e um arquivo JSON sanitizado. Nunca repara, limpa
nem altera o computador.

A ferramenta já funciona para uso pessoal supervisionado no **Modo Simples**.
Ainda está em desenvolvimento, em validação de compatibilidade e em preparação
para distribuição; trate cada resultado como apoio à revisão e espere arestas.

## Conteúdo

- [Visão geral](#visão-geral)
- [Status do projeto](#status-do-projeto)
- [Principais recursos](#principais-recursos)
- [Como funciona](#como-funciona)
- [Capacidades de diagnóstico](#capacidades-de-diagnóstico)
- [Relatórios](#relatórios)
- [Privacidade e segurança](#privacidade-e-segurança)
- [Requisitos](#requisitos)
- [Primeiros passos](#primeiros-passos)
- [Modos disponíveis](#modos-disponíveis)
- [Uso como skill de agente](#uso-como-skill-de-agente)
- [Limitações](#limitações)
- [Desenvolvimento e validação](#desenvolvimento-e-validação)
- [Capturas de tela](#capturas-de-tela)
- [Documentação](#documentação)
- [Licença](#licença)
- [Marcas e não afiliação](#marcas-e-não-afiliação)
- [Aviso legal](#aviso-legal)

## Visão geral

O FIX MY PC ajuda a entender o estado de um PC com Windows: armazenamento, logs
de eventos, itens de inicialização, amostras de desempenho e informações do
sistema operacional. Cada achado mostra a evidência, o limiar documentado, suas
limitações e a verificação humana que deve confirmá-lo.

A maioria dos "limpadores de PC" mistura diagnóstico com reparo. O FIX MY PC só
diagnostica. O que não puder ser lido é informado como desconhecido, e dado
desconhecido nunca vira afirmação de saúde nem de falha.

Ele **não** é certificação de saúde, verificação de garantia de hardware,
auditoria de segurança nem substituto de um diagnóstico profissional.

## Status do projeto

| Item | Situação |
|---|---|
| Estágio | **Em desenvolvimento — Versão funcional de prévia** (versão 0.1.0) |
| Modo Simples | Validado em uma execução supervisionada no Windows 11 Enterprise com Windows PowerShell 5.1 |
| Modo Completo | Implementado e coberto por testes sintéticos. **Ainda não validado em hardware real** |
| Windows 10, PowerShell 7 | Não validados e não suportados |
| Versão pública | **Não aprovada.** Pendências: revisão jurídica, validação em hardware e em máquina virtual, checksums publicados |

As pendências de lançamento estão em
[`distribution-manifest.json`](distribution-manifest.json),
[`docs/reviews/PUBLIC-RELEASE-REMEDIATION-PLAN.md`](docs/reviews/PUBLIC-RELEASE-REMEDIATION-PLAN.md)
e [`NOTICE.md`](NOTICE.md).

## Principais recursos

- **Estritamente somente leitura.** Um analisador estático baseado em AST confere
  o código-fonte contra listas permitidas de comandos, parâmetros e membros antes
  de carregar os módulos da aplicação. Sem reparos, sem elevação, sem acesso à
  rede.
- **Consentimento explícito antes de qualquer coleta**, com a pasta de saída e a
  política exibidas antes.
- **Seis coletores** (sistema, eventos, inicialização, desempenho, armazenamento
  e avançado) e um **motor determinístico de 22 regras**.
- **Pontuação de 0 a 100 explicável**, com **risco** diagnóstico, **cobertura** e
  **confiança** informados separadamente.
- **Sete estados de verificação** (`pass`, `finding`, `unknown`, `unsupported`,
  `access_denied`, `not_collected`, `error`). Dado ausente nunca melhora nem piora
  a pontuação.
- **Relatório HTML autocontido** em português do Brasil ou inglês, responsivo,
  com botão **Imprimir / Salvar em PDF**.
- **JSON sanitizado**, que mascara caminhos, contas e identificadores
  semelhantes.
- **Pasta de saída privada**, criada pela própria ferramenta com permissões
  restritas.

## Como funciona

```
Consentimento  →  Coleta somente leitura  →  Análise determinística  →  Relatório HTML + JSON
```

1. **Consentimento.** A ferramenta explica a política de somente leitura, mostra
   onde os arquivos serão gravados e pede sua confirmação.
2. **Coleta.** Os coletores leem informações locais do Windows (CIM, logs de
   eventos, registro, tarefas agendadas e fontes semelhantes). Nada é instalado,
   alterado ou enviado.
3. **Análise.** As regras de [`rules/rules.json`](rules/rules.json) transformam a
   evidência em achados, pontuação, nível de risco, cobertura e confiança. Esta
   etapa não usa IA nem rede.
4. **Relatório.** `report.html` e `diagnostic-sanitized.json` são gravados na
   pasta de saída. Nada é corrigido automaticamente.

## Capacidades de diagnóstico

| Coletor | O que examina |
|---|---|
| Sistema | Informações do sistema operacional e do hardware, tempo ligado, informações de ciclo de vida de um retrato embutido |
| Eventos | Logs System e Application (Erro e Crítico, últimos 7 dias): eventos críticos recorrentes, concentração de erros, erros de hardware WHEA, desligamentos inesperados, bug checks |
| Desempenho | Amostras curtas de CPU, memória e memória comprometida, coletadas uma vez durante a execução |
| Inicialização | Entradas Run/RunOnce, pastas Inicializar, tarefas agendadas de logon e serviços automáticos, listados e nunca executados |
| Armazenamento | Espaço livre, saúde do disco informada pelo Windows, status de previsão de falha SMART, eventos de erro de armazenamento |
| Avançado (somente Modo Completo) | Dispositivos com código de problema, status do Windows Defender, aplicativos instalados a partir de fontes passivas do registro, indicadores de reinício pendente, recência de hotfixes, eventos de Segurança quando acessíveis |

As 22 regras, seus limiares e penalidades estão documentados em
[`docs/methodology.md`](docs/methodology.md), que está em português.

## Relatórios

- **HTML offline.** Um único arquivo autocontido: CSS local, sem recursos
  externos, Content-Security-Policy restritiva e conteúdo escapado. Seu único
  script serve ao botão de impressão e é fixado por SHA-256 na política.
- **Pontuação.** De 0 a 100, começa em 100 e é reduzida apenas por achados
  comprovados, com teto por categoria. Pesos: Armazenamento 30, Eventos 25,
  Desempenho 20, Inicialização 15, SO 10. Só entram na pontuação as categorias com
  regra penalizante e evidência; na versão 0.1.0 a Inicialização não tem regra
  penalizante.
- **Risco.** Um nível de risco diagnóstico separado da pontuação. Uma falha
  crítica de armazenamento comprovada define o risco como crítico e limita a
  pontuação a 49.
- **Cobertura e confiança.** A cobertura indica quantas verificações aplicáveis
  foram concluídas. Abaixo de 60% a pontuação é marcada como provisória; abaixo de
  35%, fica indisponível. Um 100 provisório significa "nenhum problema encontrado
  nas verificações concluídas", nunca saúde comprovada.
- **Limitações.** Todo relatório lista o que não pôde ser lido e por quê.
- **JSON sanitizado.** `diagnostic-sanitized.json` segue
  [`schemas/diagnostic.schema.json`](schemas/diagnostic.schema.json).
- **Imprimir / Salvar em PDF.** Clique no botão do cabeçalho do relatório (ou
  pressione Ctrl+P) para abrir a janela de impressão do próprio navegador e
  escolher "Salvar como PDF". O layout é A4 e oculta o botão na impressão. Nenhuma
  biblioteca de PDF é usada.

| Arquivo | Conteúdo |
|---|---|
| `report.html` | O relatório visual |
| `diagnostic-sanitized.json` | Diagnóstico redigido, evidências, achados e pontuação |
| `diagnostic-internal.json` | Criado somente com `-IncludeInternalJson`; mantenha-o privado |

## Privacidade e segurança

- **Execução local.** O script coleta e analisa no seu computador. Não tem acesso
  à rede por projeto e não envia relatórios a lugar nenhum.
- **Política somente leitura.** As únicas gravações são os arquivos do relatório
  dentro da pasta de saída que você autorizar. Veja
  [`docs/readonly-policy.md`](docs/readonly-policy.md) para as camadas de
  aplicação da política e seus limites.
- **Consentimento explícito.** A coleta não começa sem ele. O parâmetro
  `-AcceptReadOnlyPolicy` é uma declaração de quem escreve a linha de comando;
  não prova que um humano concordou.
- **Pasta de saída restrita.** A ferramenta cria a pasta com permissões limitadas
  à sua conta e ao SYSTEM e sem herança da pasta pai. Recusa pastas existentes,
  pontos de reanálise (*reparse points*) e caminhos de rede, e nunca altera as
  permissões de pastas existentes. Administradores locais ainda podem ler arquivos
  do computador.
- **Pastas sincronizadas na nuvem.** Antes de pedir o consentimento, a ferramenta
  avisa quando a pasta está em uma unidade sem permissões do Windows (FAT/exFAT)
  ou dentro do OneDrive, cujas cópias podem sair do computador. Mantenha a saída
  fora de pastas sincronizadas se isso importar para você.
- **Limites da sanitização.** O JSON sanitizado mascara caminhos, contas e campos
  semelhantes, e omite números de série, chaves de produto, argumentos de
  processos e mensagens brutas de eventos. Não é anonimização: nomes de produtos,
  processos, provedores e dispositivos ainda podem identificar softwares
  instalados. Revise o arquivo antes de compartilhar.
- **Modo skill e serviços de IA.** Executar o script localmente e pedir que um
  agente de IA o execute são coisas diferentes. No modo skill, o agente lê o
  `diagnostic-sanitized.json` e a saída do console (que inclui caminhos locais).
  Esse conteúdo é então processado pelo serviço de IA usado pelo agente, conforme
  a configuração e os termos desse provedor. Use o modo skill só se estiver de
  acordo com isso, ou execute o script você mesmo e não compartilhe nada.

## Requisitos

Ambiente validado:

- Windows 11
- Windows PowerShell 5.1 (`powershell.exe`)
- Conta de usuário comum. Direitos de administrador não são necessários e não
  devem ser usados.

Windows 10 e PowerShell 7 (`pwsh`) não foram validados e não são suportados.

## Primeiros passos

Ainda não há versão pública nem download. Se você recebeu uma cópia do
proprietário do projeto, extraia-a em uma pasta sob seu controle e execute os
comandos abaixo a partir dela, no Windows PowerShell 5.1.

Execução interativa (explica a política e pergunta idioma, modo e consentimento):

```powershell
powershell -NoProfile -File .\fixmypc.ps1
```

Execução não interativa. `-OutDir` deve ser um caminho local absoluto que **ainda
não existe**; a ferramenta o cria. Adicione `-AcceptReadOnlyPolicy` somente se você
mesmo confirmar a política de somente leitura para esta execução:

```powershell
powershell -NoProfile -File .\fixmypc.ps1 `
  -Mode simple -Language pt-BR `
  -OutDir "$env:LOCALAPPDATA\FixMyPC\auditoria-1" -AcceptReadOnlyPolicy
```

Sem `-OutDir`, o relatório vai para uma nova pasta em `%LOCALAPPDATA%\FixMyPC`.

Outros comandos seguros:

```powershell
# Verificar a política de somente leitura do próprio código-fonte (sem coletar dados do sistema)
powershell -NoProfile -File .\fixmypc.ps1 -ValidateOnly

# Demonstração sintética a partir de uma fixture (sem nenhum acesso ao sistema)
powershell -NoProfile -File .\fixmypc.ps1 `
  -Fixture .\tests\fixtures\demo-synthetic.json -Mode full -Language pt-BR -Yes

# Mostrar a ajuda de uso
powershell -NoProfile -File .\fixmypc.ps1 -Help
```

Os comandos respeitam a política de execução efetiva do seu PowerShell. Se ela
bloquear o script, siga o procedimento aprovado da sua organização. Não
desative o Windows Defender nem reduza a segurança de todo o computador para usar
esta ferramenta.

Códigos de saída: `0` sucesso · `2` violação da política de somente leitura (não
contorne) · `3` erro de entrada ou de consentimento · `4` falha de execução.

Para remover o FIX MY PC, apague a pasta que você extraiu e, se não precisar mais
deles, as pastas de relatório que você criou. Nada mais é instalado.

## Modos disponíveis

| Modo | O que executa | Validação |
|---|---|---|
| `simple` | Sistema, eventos, inicialização, desempenho, armazenamento | Validado em uma execução supervisionada no Windows 11 Enterprise, usuário comum, PowerShell 5.1 |
| `full` | Modo Simples mais dispositivos, Defender, aplicativos instalados, indicadores de reinício pendente, recência de hotfixes e eventos de Segurança quando acessíveis | Implementado e testado somente com dados sintéticos. Não validado em hardware real |

"Implementado" significa que o código existe e passa nos testes sintéticos.
"Validado" significa que foi executado em uma máquina real sob supervisão.

## Uso como skill de agente

O [`SKILL.md`](SKILL.md) transforma este repositório em uma skill do padrão
[Agent Skills](https://agentskills.io) (adaptadores compatíveis com Claude Code e
Codex: [`adapters/claude/README.md`](adapters/claude/README.md),
[`adapters/codex/AGENTS.md`](adapters/codex/AGENTS.md)). O contrato do agente
proíbe alterar o computador, inventar comandos de coleta ou contornar o
consentimento.

**`-AcceptReadOnlyPolicy` não prova que um humano autorizou a execução.** Um
agente pode adicioná-lo sem perguntar. O consentimento deve ser pedido à pessoa a
cada execução real (comando exato, modo, idioma e pasta de saída), nunca
reaproveitado e nunca guardado em script, hook ou permissão permanente. Veja
[Privacidade e segurança](#privacidade-e-segurança) para saber o que o serviço de
IA do agente recebe.

## Limitações

- **O SMART pode estar indisponível.** Ele pode exigir permissões ou suporte de
  driver que um usuário comum não tem. SMART indisponível significa "desconhecido",
  não "saudável".
- **Alguns coletores exigem permissões que o usuário comum não tem** (por exemplo,
  o log de Segurança). São informados como `access_denied` e reduzem a cobertura e
  a confiança; não reduzem a pontuação.
- **Consultas ao Windows podem demorar ou travar.** As consultas a logs de eventos
  e a tarefas agendadas não têm tempo limite embutido. Se uma execução travar,
  pressione Ctrl+C; os arquivos do relatório só são gravados na fase final.
- **Um relatório sem achados não é garantia.** As regras são conservadoras e
  amostram um instante; a ausência de achados não prova a ausência de problemas.
- **Compatibilidade limitada.** Só o ambiente descrito em
  [Requisitos](#requisitos) foi exercitado, e apenas o Modo Simples em hardware
  real.
- **Lacunas menores conhecidas:** destinos de atalhos (`.lnk`) de inicialização
  não são resolvidos; a verificação Authenticode não é coletada; as datas de ciclo
  de vida do Windows vêm de um retrato embutido que pode ficar desatualizado;
  varreduras pendentes do Windows Update deliberadamente não são executadas.
- **Ainda em desenvolvimento.** Interfaces, regras e layout do relatório podem
  mudar.

## Desenvolvimento e validação

Últimos resultados registrados (Etapa 11, sintéticos e offline):

| Suíte | Resultado |
|---|---|
| `tests/Run.Tests.ps1` | 453 / 453 |
| `tests/Collector.Tests.ps1` | 85 / 85 |
| `tests/Visual.Tests.ps1` | 307 / 307 |
| `-ValidateOnly` | aprovado |
| Verificação do manifesto de distribuição | aprovada |

Essas suítes usam fixtures sintéticas e mocks isolados. Elas verificam o código e
o relatório, **não** o comportamento em hardware real, e não são uma homologação
de hardware. A única evidência em hardware real até agora é uma execução
supervisionada do Modo Simples em uma única máquina com Windows 11 Enterprise. O
Modo Completo, outras edições e versões do Windows, a homologação em máquina
virtual e as políticas corporativas (AppLocker, WDAC, Constrained Language Mode)
continuam pendentes; veja [`docs/homologation-plan.md`](docs/homologation-plan.md).

```powershell
powershell -NoProfile -File .\tests\Run.Tests.ps1
powershell -NoProfile -File .\tests\Collector.Tests.ps1
powershell -NoProfile -File .\tests\Visual.Tests.ps1
powershell -NoProfile -File .\tools\Test-DistributionManifest.ps1
```

## Capturas de tela

As duas imagens mostram um **relatório de demonstração sintético**: todos os
valores são fictícios e nenhum computador real é descrito.

![Relatório de demonstração sintético com o botão Imprimir / Salvar em PDF, em português](docs/screenshots/stage10-print-btn-ptBR-1440.png)

![Relatório de demonstração sintético, em inglês, com um achado crítico de armazenamento](docs/screenshots/stage71-final-critical-en-1440.png)

Mais exemplos sintéticos estão em [`samples/`](samples/).

## Documentação

A documentação técnica em `docs/` está em português; o `CHANGELOG.md` está em
inglês.

- [`docs/readonly-policy.md`](docs/readonly-policy.md): a política de somente
  leitura, as camadas de aplicação e seus limites.
- [`docs/methodology.md`](docs/methodology.md): estados, severidades, pontuação,
  cobertura, confiança e as 22 regras.
- [`docs/visual-integration.md`](docs/visual-integration.md): identidade visual e
  assets do relatório.
- [`docs/homologation-plan.md`](docs/homologation-plan.md): validação planejada.
- [`CHANGELOG.md`](CHANGELOG.md) e [`NOTICE.md`](NOTICE.md).

## Licença

O FIX MY PC é licenciado sob a
[PolyForm Noncommercial License 1.0.0](LICENSE). Em resumo: você pode usar,
estudar, modificar e redistribuir para fins não comerciais, sem custo. O uso
comercial não é concedido e exige autorização escrita específica do proprietário
do projeto. O texto em [`LICENSE`](LICENSE) é a única declaração vinculante.

É uma licença de código disponível (*source-available*); **não** é uma licença de
código aberto aprovada pela OSI.

A licença cobre o software. O nome FIX MY PC, o logotipo e a arte v2 são tratados
à parte: sua titularidade ainda não está registrada e o nome do produto aguarda
revisão jurídica. Veja [`NOTICE.md`](NOTICE.md). A publicação pública continua
bloqueada até que esses itens sejam resolvidos.

## Marcas e não afiliação

O FIX MY PC é um projeto independente. **Não é afiliado, endossado, patrocinado
nem aprovado pela Microsoft.** Windows é marca da Microsoft Corporation, citada
aqui apenas para indicar compatibilidade. Veja [`NOTICE.md`](NOTICE.md).

## Aviso legal

O FIX MY PC informa; não repara, não limpa e não reconfigura nada. Os resultados
exigem interpretação adequada: use a verificação humana recomendada em cada achado
e consulte um técnico qualificado para decisões sobre seu hardware, seus dados ou
sua segurança. A pontuação é um apoio à revisão, não um diagnóstico de hardware,
uma garantia nem uma certificação de segurança. O software é fornecido nos termos
da licença, incluindo sua cláusula "No Liability" (sem responsabilidade).
