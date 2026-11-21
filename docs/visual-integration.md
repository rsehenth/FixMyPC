# Integração visual do laudo HTML

Este documento explica como a identidade visual entra no `report.html` sem
quebrar as garantias do produto: **offline, sem rede, sem modificar o Windows e
sem JavaScript além do script estático do botão de impressão, autorizado por hash**. A aprovação visual não equivale à homologação dos
coletores nem à autorização de publicação.

## 1. Estrutura de arquivos

```text
assets/
├── branding/                     FONTES v2 (identidade aprovada)
│   ├── fixmypc-logo-v2.png       2172x724, PNG com transparência
│   └── fixmypc-icon-v2.png       1254x1254, PNG com transparência
├── report/                       FONTES v2
│   ├── fixmypc-report-banner-v2.png 2172x724, opaco (fundo azul-marinho)
│   └── fixmypc-{overview,hardware,findings,startup,storage,privacy}-v2.png
├── brand-review.json             revisão de marca por hash de fonte (gate do FMP-10)
└── optimized/                    VARIANTES geradas no desenvolvimento
    ├── manifest.json             chave, mime, dimensões, bytes, SHA-256, origem
    ├── branding/*.png            logo (720 px) e ícone (96 px), RGBA
    ├── report/*.png|jpg          ícones de seção (144 px) e banner (1440 px)
    └── embed/<chave>.b64         payload Base64 lido pelo renderizador
tools/
├── Optimize-Assets.ps1           gera assets/optimized (somente desenvolvimento)
└── Render-Samples.ps1            gera os relatórios sintéticos de demonstração
```

Fontes v2, variantes PNG/JPEG (para inspeção) e payloads Base64 (para o HTML) ficam em
pastas separadas. As fontes nunca são lidas pelo renderizador; o relatório usa só
`manifest.json` e `embed/*.b64`.

## 2. Como as imagens chegam ao HTML

1. **Empacotamento (fora da auditoria).** `tools/Optimize-Assets.ps1` usa
   apenas `System.Drawing`, que acompanha o Windows PowerShell 5.1. Ele
   redimensiona com interpolação bicúbica, preserva o canal alfa dos PNGs,
   grava o Base64 e registra tamanho, dimensões e SHA-256 em `manifest.json`.
   O banner é opaco e vira JPEG (qualidade 88): 1,5 MB em PNG ficaria em
   1,06 MB mesmo reduzido; em JPEG fica em 102 KB.
2. **Auditoria.** `Get-FmpEmbeddedAssets` (em `HtmlRenderer.ps1`) apenas lê
   `manifest.json` e `embed/*.b64`. Nenhuma imagem é decodificada,
   redimensionada ou baixada durante a execução, e nenhum comando novo entrou na
   lista permitida do scanner AST (a política somente leitura não mudou).
3. **Validação por asset.** O payload só é aceito se:
   - a chave está entre as nove conhecidas e consta no manifesto;
   - o mime é `image/png` ou `image/jpeg` (SVG e HTML são recusados);
   - o caminho casa com `^embed/[a-z]+\.b64$` e não contém reparse points;
   - bytes, largura e altura do manifesto estão em faixas válidas
     (até 400 KiB por asset, até 4096 px, no máximo 1,5 MiB somados);
   - o texto tem exatamente `4 * ceil(bytes / 3)` caracteres, usa só o alfabeto
     Base64 e começa com a assinatura de PNG (`iVBORw0KGgo`) ou JPEG (`/9j/`).
4. **Falha segura.** Qualquer asset ausente, vazio, truncado ou suspeito é
   descartado individualmente, o motivo fica em `Get-FmpAssetIssues` e o laudo
   usa o fallback em texto (cabeçalho "FIX MY PC" em CSS). O relatório nunca
   deixa de ser gerado por causa de imagem.

O HTML final usa `<img src="data:image/...;base64,...">`; o ícone principal
também vira favicon. Todas as imagens têm `width`/`height` para evitar saltos
de layout, e o CSS impõe `max-width: 100%; height: auto`.

## 3. Política de segurança (CSP)

```text
default-src 'none'; script-src 'sha256-<hash do script de impressão>';
style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'
```

- `img-src data:` só é emitido quando pelo menos um asset passou na validação;
  sem imagens, a diretiva some e `default-src 'none'` bloqueia tudo.
- `script-src` aceita somente o hash SHA-256 (bytes UTF-8) do único script do
  documento, calculado pelo renderizador (`Get-FmpPrintScriptHash`). O script
  revela o botão e chama `window.print()` apenas no clique; não lê dados do laudo,
  não faz requisições e não grava nada. Qualquer alteração no script muda o hash
  e o navegador o bloqueia. Sem `unsafe-inline`/`unsafe-eval` em `script-src`.
  Detalhes: `docs/reviews/OPUS-5.5-STAGE10-PRINT-PDF.md`.
- `style-src 'unsafe-inline'` já existia: o CSS é local, validado contra
  `<`, `@import` e `url(`; os `style="width:NN%"` das barras são números
  limitados a 0–100 gerados pelo renderizador, nunca texto de dados.
- Todo texto vindo dos dados passa por `HtmlEncode`; URLs dos dados nunca viram
  links. Os ícones SVG de severidade são marcação estática escrita no código.

## 4. Mapa dos assets

| Asset | Uso | Tratamento |
|---|---|---|
| `fixmypc-report-banner` | topo do laudo (tela) | `alt` informativo; oculto na impressão; recortado a 260 px de altura em telas largas (`object-fit: cover`) |
| `fixmypc-logo` | cabeçalho compacto da impressão A4 | fundo transparente sobre branco |
| `fixmypc-icon` | favicon e rodapé | decorativo no rodapé |
| `overview`, `findings`, `hardware`, `storage`, `startup`, `privacy` | título da seção correspondente | `alt=""` + `aria-hidden`, 46 px dentro de um bloco azul claro |

A seção de eventos e as demais sem arte própria não recebem imagem inventada.
A arte v2 é decorativa e neutra (sem escudo de aprovação nem medidor): ainda assim fica
pequena e nunca substitui o texto de estado da auditoria.

### 4.1 Identidade v2 e fechamento do FMP-10 (etapa 7.1)

A arte anterior (logotipo de quatro painéis do Windows, escudos com check, medidores)
foi **removida** do projeto e substituída pela identidade v2: monitor genérico com painéis
abstratos, lupa e linha de pulso, em azul-marinho/ciano/teal, sem marcas de terceiros. Os
hashes da arte retirada ficam fixados em `tests/Visual.Tests.ps1` (V12) para que ela não
volte, nem como fonte nem como Base64 embutido.

- `assets/brand-review.json` registra, por asset e por hash de fonte, a revisão visual:
  sem logotipo do Windows, sem outras marcas, sem escudo/check de aprovação, sem medidor
  de saúde fixo. Se a arte mudar sem nova revisão, o teste falha.
- A arte é **decorativa**: não representa medições. Nota, cobertura, confiança e
  `riskLevel` vêm só dos dados calculados.
- Revisão visual não é revisão jurídica. O nome do produto continua contendo "Windows"
  (ver `NOTICE.md`).

## 5. Regenerar ou adicionar assets

```powershell
powershell -NoProfile -File tools\Optimize-Assets.ps1
powershell -NoProfile -File tests\Visual.Tests.ps1
```

Para trocar uma arte, salve a nova fonte em `assets/branding` ou `assets/report` com um
nome novo (`...-v3.png`), aponte `tools/Optimize-Assets.ps1` para ela, execute o primeiro
comando, atualize o hash fixado em `tests/Visual.Tests.ps1` (V12) e **refaça a revisão de
marca** em `assets/brand-review.json` (o teste exige um registro para o hash atual). Para
incluir uma nova chave, acrescente-a em `tools/Optimize-Assets.ps1` **e** em
`$script:FmpAssetKeys` (`HtmlRenderer.ps1`); sem essa segunda alteração o renderizador a
ignora de propósito. Distribua `assets/optimized/manifest.json` e `assets/optimized/embed/`
junto com a skill; `tools/`, as fontes v2 e `brand-review.json` são só de desenvolvimento.

## 6. Impressão A4

O CSS `@media print` esconde banner, navegação e link de pulo; mostra o logo
compacto, remove sombras, mantém as barras e selos com `print-color-adjust:
exact` (as barras continuam visíveis com "gráficos de plano de fundo"
desligado), evita quebrar achados, cartões e linhas, repete o cabeçalho das
tabelas e coloca `Página N / M` no rodapé via `@page`. O identificador da
execução está no título do documento (cabeçalho padrão do navegador e nome
sugerido ao salvar em PDF) e no bloco de metadados da primeira página; CSS
estático não consegue injetar o identificador em cada rodapé.

O texto do rodapé de página (`@bottom-left`) vem da chave `report.print.footer`
do idioma do laudo: o renderizador o acrescenta ao CSS depois de remover aspas,
barra invertida, `<`, `>` e caracteres de controle. O `style.css` estático não
tem texto fixo de rodapé.

## 6.1 Alto contraste (`forced-colors`)

Em modo de alto contraste o navegador descarta fundos. O bloco
`@media (forced-colors: active)` pinta as barras (`Highlight` sobre `Canvas`
com borda `CanvasText`), dá borda real aos selos de severidade/estado e ao
indicador `risk`, e remove as marcações decorativas do medidor. Verificado só
por inspeção do CSS e por teste de texto; não houve teste em Windows com tema de
alto contraste real.

## 7. Teste

`tests/Visual.Tests.ps1` (198 asserções, executado por `Run.Tests.ps1`) valida
os assets reais (SHA-256, assinatura, dimensões, alfa), o HTML gerado em PT-BR
e EN, ausência de JavaScript além do script de impressão autorizado por hash e de recursos externos, CSP, escape com conteúdo
malicioso e Unicode, campos vazios, nota provisória/indisponível, cobertura
parcial, conteúdo longo, assets ausentes ou corrompidos, regras de impressão e
responsividade e paridade dos idiomas. A inspeção visual é manual e está
descrita em `docs/reviews/SONNET-5.5-VISUAL-REVIEW.md`.
