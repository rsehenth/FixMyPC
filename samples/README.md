# samples/ — demonstração com dados sintéticos

**Todos os arquivos desta pasta foram gerados a partir de
`tests/fixtures/demo-synthetic.json` — uma máquina fictícia. Nenhum valor
descreve um computador real.**

O relatório HTML exibe um aviso permanente de "DADOS SINTÉTICOS" no topo.

Para reproduzir (por padrão em uma pasta nova de `%LOCALAPPDATA%\FixMyPC`), execute a partir de `samples`.

```powershell
powershell -NoProfile -File ..\fixmypc.ps1 `
  -Fixture ..\tests\fixtures\demo-synthetic.json `
  -Mode full -Language pt-BR -IncludeInternalJson -Yes
```

- `demo-report.html` / `demo-report.en.html` — relatório de demonstração em PT-BR e EN (abrir no navegador).
- `visual/` — estados sintéticos, em PT-BR e EN, gerados por `tools/Render-Samples.ps1` (só lê `tests/fixtures`): sem risco detectado (`none-detected.*`), risco crítico com nota limitada a 49 (`critical.*`, fixture `critical-disk.json`), acesso negado em coletores (`access-denied.*`), nota provisória (`provisional.*`) e nota indisponível (`unavailable.*`). O risco elevado é o próprio `demo-report*.html`.
- `demo-diagnostic-sanitized.json` — JSON sanitizado correspondente.
- `demo-diagnostic-internal.json` — JSON interno correspondente (sintético).
