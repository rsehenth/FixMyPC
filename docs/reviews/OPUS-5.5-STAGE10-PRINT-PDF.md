# FIX MY PC — Etapa 10: botão Imprimir / Salvar em PDF

Data: 21/11/2026 · Executor: Claude Opus 5.5

## 1. Resultado

O laudo HTML tem um botão **Imprimir / Salvar em PDF** (EN: **Print / Save as PDF**) no cabeçalho. O clique abre a janela de impressão nativa do navegador (equivalente a Ctrl+P), onde a pessoa escolhe impressora, "Salvar como PDF", páginas e orientação, ou cancela. Não há gerador de PDF, biblioteca, rede ou armazenamento.

## 2. Arquivos alterados

| Arquivo | Mudança |
|---|---|
| `src/reports/HtmlRenderer.ps1` | `$script:FmpPrintScript`, `Get-FmpPrintScriptHash`, ícone `print`, marcação do botão no cabeçalho, `<script>` no fim do `body`, CSP com o hash |
| `src/security/ReadOnlyPolicy.ps1` | Exceção restrita ao papel `writer`: `SHA256::Create().ComputeHash` e `[Convert]::ToBase64String` |
| `templates/style.css` | `.hero-top`, `.print-action`, `.print-btn` (hover, ativo, foco, `[hidden]`), regra mobile ≤640 px, `forced-colors`, oculto em `@media print` |
| `locales/pt-BR.json`, `locales/en.json` | `report.print.button`, `report.print.hint` |
| `tests/Visual.Tests.ps1`, `tests/Run.Tests.ps1` | Contrato novo (só o script autorizado) e suite V13 |

## 3. Localização

Dentro de `header.hero > .hero-meta`, na mesma linha dos selos (Somente leitura · Modo · Sintético), alinhado à direita no desktop, com a dica "Você também pode usar Ctrl+P." abaixo. Em telas ≤640 px ocupa a largura inteira, centralizado, sem sobrepor o título nem o cartão de nota (que fica em outra seção).

## 4. Script e CSP

Script (bytes exatos, UTF-8, sem BOM):

```js
(function(){var b=document.getElementById("fmp-print");if(!b){return;}b.hidden=false;b.addEventListener("click",function(){window.print();});})();
```

- O botão é emitido com `hidden`. O script o revela e liga o clique. Se a CSP bloquear o script (adulteração, navegador antigo, JS desativado), o botão continua oculto e só a dica Ctrl+P aparece: não existe controle morto.
- `window.print()` só é chamado dentro do handler de clique. Nada roda automaticamente.
- O script lê somente o elemento `#fmp-print`. Não acessa dados do laudo, rede, cookies, `localStorage`, timers ou `eval`.
- Hash CSP atual: `sha256-KJzMA/LPo3dojY5+SKhGJu13nzTwvWXnwmdoyoBK0g4=`, calculado pelo renderizador a cada geração sobre os bytes UTF-8 do script e conferido de forma independente (Python `hashlib` e o próprio teste V13).

CSP resultante:

```text
default-src 'none'; script-src 'sha256-KJzMA/LPo3dojY5+SKhGJu13nzTwvWXnwmdoyoBK0g4='; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'
```

Preservados: `default-src 'none'`, `base-uri 'none'`, `form-action 'none'`, `img-src data:` condicional. Não usados: `unsafe-inline`/`unsafe-eval` em `script-src`, `onclick`, `javascript:`, scripts externos, CDN.

## 5. Garantias e limitações

- Garantia: qualquer byte alterado no script muda o hash e o navegador recusa executá-lo (verificado em Chromium: console registra a violação de `script-src`, botão permanece oculto).
- A CSP vem de `<meta http-equiv>`, então quem edita o arquivo HTML pode editar também a CSP. O hash protege contra alteração do script isolada, não contra quem reescreve o documento inteiro. Abrir HTML de origem desconhecida continua sendo decisão do usuário.
- A abertura real do diálogo de impressão não pode ser observada por automação. A chamada foi verificada por instrumentação (`window.print` substituído por um contador via `addInitScript`).

## 6. Testes em navegador (Chromium via Playwright, `file://`, offline)

| Verificação | PT-BR | EN |
|---|---|---|
| Botão visível após o script | sim | sim |
| Texto exato | Imprimir / Salvar em PDF | Print / Save as PDF |
| Chamadas a `window.print` no carregamento | 0 | 0 |
| Tab: link de pulo → botão; Enter | 1 chamada | — |
| Clique | +1 chamada | 1 chamada |
| `document.scripts.length` | 1 | 1 |
| Overflow horizontal a 320/375/768/1024 px | 0 | 0 |
| `.print-action` em mídia print | `display: none` | `display: none` |
| Requisições não `file:`/`data:` | 0 | 0 |
| Cópia com script adulterado (`window.print( )`) | botão oculto, dica visível, violação CSP no console | — |

Não testados: Edge (canal específico), Firefox, leitor de tela, impressão física. 320 px de largura equivale a 400% de zoom em tela de 1280 px.

## 7. Impressão A4

O CSS de impressão existente (A4, margens 14/13/18 mm, rodapé localizado, contador de páginas, `break-inside: avoid` em cartões, achados e linhas, cabeçalho de tabela repetido, cores de risco com `print-color-adjust: exact`, cartão sticky desligado) foi mantido; só acrescentei a ocultação do botão. PDF gerado pelo Chromium do relatório crítico EN: 12 páginas A4 (595 × 842 pt). Os estados sem achados, provisório, indisponível, crítico e de conteúdo longo usam o mesmo CSS e foram verificados em etapas anteriores (`docs/screenshots/stage71-print-*`).

## 8. Evidências visuais

- `docs/screenshots/stage10-print-btn-ptBR-1440.png` — cabeçalho desktop
- `docs/screenshots/stage10-print-btn-focus-ptBR-1440.png` — foco por teclado
- `docs/screenshots/stage10-print-btn-ptBR-375.png`, `...-320.png` — celular
- `docs/screenshots/stage10-print-btn-en-768.png` — tablet EN
- `docs/screenshots/stage10-print-a4-critical-en-p1.png` — emulação de impressão A4, sem botão

## 9. Regressões

- Visual.Tests V2/V3/V9/V12: "zero `<script>`" passou a "exatamente um `<script>`, idêntico ao autorizado, e nenhum outro"; CSP exata com o hash recalculado pelo teste.
- Visual.Tests V13 (17 verificações): presença e texto PT/EN, fallback Ctrl+P, botão nativo único antes do `h1`, `hidden` até o script, `window.print` só no handler, ausência de APIs de rede/armazenamento, script no fim do `body`, sem `onclick`/`javascript:`, hash adulterado não autorizado, hash do renderer = hash do teste, CSS (impressão, `[hidden]`, foco, 40 px, mobile, alto contraste).
- Run.Tests: asserções de demo/degenerate/XSS adaptadas para remover só a tag autorizada antes de procurar scripts.
