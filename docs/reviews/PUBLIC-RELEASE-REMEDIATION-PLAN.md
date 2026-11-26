# FIX MY PC — Plano de fechamento para publicação pública

Data: 21/11/2026 · Base: `OPUS-5.5-STAGE10-PUBLIC-RELEASE-AUDIT.md`

Só o que falta. Itens corrigidos na Etapa 10 não aparecem aqui.

## A. Obrigatório antes de publicar

| # | Pendência | Responsável recomendado | Ação necessária | Teste de aceite |
|---|---|---|---|---|
| A1 | ~~Licença (`LICENSE-PENDING`)~~ **Resolvido na Etapa 11.1** | Proprietário | Licença vigente: MIT (SPDX `MIT`), Copyright (c) 2026 Lucas Sehenth, em substituição à PolyForm Noncommercial 1.0.0 escolhida na Etapa 11.1; `LICENSE`, `NOTICE.md`, `SKILL.md` e READMEs foram alinhados. Resta no A2: direitos sobre a arte v2 (a MIT não os concede) e nome/marca. | `Test-DistributionManifest` PASS (verificado) |
| A2 | Revisão jurídica de nome/marca (`LEGAL-REVIEW`) e titularidade da arte v2 | Proprietário + revisão jurídica | Decidir uso de "Windows" no nome/tagline e registrar autoria/direitos dos nove assets. | Parecer registrado; bloqueio removido pelo proprietário |
| A3 | Homologação em VM | Operador autorizado | Executar `docs/homologation-plan.md` em VM descartável: Windows 11 23H2/24H2/25H2 Home/Pro/Enterprise, usuário comum e administrador, Modo Simples e Completo, PS 5.1; Windows 10 22H2 e PS 7 só se forem anunciados. Monitorar escrita, rede e duração (ProcMon). | Zero escrita fora de `-OutDir`, zero rede, exit 0, laudos coerentes com o estado conhecido da VM; resultados por cenário registrados |
| A4 | Política corporativa | Operador autorizado | Rodar na VM com AppLocker/WDAC em modo auditoria, Constrained Language Mode e política de execução `AllSigned`/`RemoteSigned` via GPO. | Falha clara e sem efeitos colaterais quando bloqueado; documentado no README |
| A5 | Timeout de `Get-WinEvent`/`Get-ScheduledTask` (S10-08) | Desenvolvimento | Decidir: (a) aceitar e documentar o risco (Ctrl+C interrompe; nada é gravado), ou (b) executar essas consultas em runspace com espera limitada e abandono, sem encerrar processos. (b) exige revisão do scanner. | (a) texto em Limitações; (b) teste com mock que trava → módulo `error` dentro do limite |
| A6 | Procedência do pacote (S10-10) | Proprietário | Decidir assinatura Authenticode. Publicar `SHA256SUMS.txt` do ZIP com a release e instrução de conferência: `Get-FileHash .\fixmypc-0.1.0.zip -Algorithm SHA256`. Nunca pedir `Set-ExecutionPolicy Bypass` global. | Hash publicado confere com o ZIP baixado em máquina limpa |
| A7 | `SECURITY.md` e `PRIVACY.md` | Proprietário | Definir canal privado de reporte de vulnerabilidades e prazo de resposta; política de privacidade curta: nada coletado pelo autor, nada enviado, onde ficam os arquivos, como apagar. | Arquivos no grupo `runtime` do manifesto; links no README |
| A8 | Revisão independente final | Agente/revisor diferente do executor | Reauditar as mudanças da Etapa 10 (CSP por hash, exceção do scanner, saída padrão, sanitizador) e os critérios do item 14 do briefing. | Parecer independente sem P0/P1 abertos |

## B. Decisões recomendadas (não bloqueiam se aceitas por escrito)

| # | Pendência | Recomendação |
|---|---|---|
| B1 | Verificação de ACL da pasta de saída (S10-09) | Aceitar o padrão `%LOCALAPPDATA%` + aviso como suficiente para v0.1. Se quiser verificação real, autorizar `Get-Acl` (somente leitura) na allowlist do papel `core` e falhar quando Users/Authenticated Users/Everyone puderem ler. |
| B2 | Volsnap em `storage.disk_event_errors` | Manter (penalidade 6) por ora; reavaliar na homologação com eventos reais. Separar exigiria nova versão de metodologia. |
| B3 | `os.w10_eol` (S10-16) | Conferir a data 25H2 Home/Pro com a página oficial; decidir cobertura de Enterprise/Education; renomear a regra numa versão futura mantendo o ID antigo no JSON. |

## C. Empacotamento

1. Gerar o ZIP somente com o grupo `runtime` do manifesto, a partir de um checkout limpo (nunca do workspace de desenvolvimento).
2. Na cópia extraída fora do workspace: `-ValidateOnly` exit 0, `-Help` exit 0, nenhum arquivo `report.html`, `diagnostic-*.json`, `.log`, cache de agente, `graphify-out/`, `tests/` ou `samples/` (procedimento usado na Etapa 10, 40 arquivos).
3. Calcular e publicar o SHA-256 (A6).

## D. Documentação a concluir

- README EN/PT-BR: requisitos (Windows 11, Windows PowerShell 5.1, sem administrador), matriz de compatibilidade com resultados de A3, links para `SECURITY.md`/`PRIVACY.md`, conferência de SHA-256. Já feito nesta etapa: saída privada padrão, salvar em PDF, remoção, compartilhamento opcional, compatibilidade honesta.
- `docs/methodology.md`: sem mudança de algoritmo nesta etapa; acrescentar a explicação de `os.w10_eol=unknown` em edições fora do retrato.

## E. Melhorias futuras (não bloqueiam)

S10-15 gravação atômica dos artefatos · S10-17 tradução de valores do provedor · S10-18 limpeza de `out\fmp-tests-*` · S10-19 rótulo redundante no CLI · testes com leitor de tela, Edge e Firefox · tempo de `-ValidateOnly` (~8 s) medido separadamente.
