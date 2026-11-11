# PsiSaas

Sistema web em português para organizar consultórios de psicologia, com Flask, SQLite e interface responsiva.

## Recursos

- Login, recuperação de senha por e-mail e autenticação em duas etapas TOTP.
- Dados isolados por profissional, com validação de acesso em todas as rotas privadas.
- Cadastro, busca, edição, exportação e exclusão de pacientes.
- Agenda presencial/online, reagendamento individual ou de uma sequência e recorrência semanal de até 52 sessões.
- Detecção de conflitos e alterações de sequência atômicas: um conflito desfaz toda a operação.
- Confirmação de presença pelo paciente com link temporário.
- Lista de espera com convites para vagas: o primeiro aceite reserva o horário.
- Lembretes automáticos por e-mail ou WhatsApp Business, com autorização do paciente e controle de duplicação.
- Controle de recebimentos por data de entrada, despesas, resultado de caixa e exportação das sessões em CSV.
- Pix copia e cola via Mercado Pago, conciliação automática com webhook verificado e emissão idempotente.
- Indicadores de faltas, ocupação da agenda, horas reservadas e valores em atraso.
- Backup criptografado e restauração verificada em novo arquivo.

## Executar localmente

Requer Python 3.12 ou superior.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app 'app:create_app()' create-user
flask --app 'app:create_app()' run
```

Abra http://127.0.0.1:5000. O comando cria uma conta com senha de pelo menos 12 caracteres. Não existem usuários ou senhas padrão. No Windows, ative `.venv\Scripts\Activate.ps1` e configure variáveis com `$env:NOME`.

A agenda, pacientes, despesas e pagamentos manuais funcionam sem provedores externos. Para segundo fator e backups, gere as chaves locais indicadas em [Operação](docs/OPERACAO.md). Recuperação de senha, mensagens automáticas e Pix precisam de serviços configurados; não são ativados apenas ao baixar o código.

[.env.example](.env.example) lista as variáveis disponíveis; a aplicação lê o ambiente do processo, sem carregar arquivos `.env` automaticamente. Mantenha as mesmas chaves entre reinicializações.

## Testar

```bash
python -m unittest discover -s tests -v
```

Os testes cobrem os fluxos de agenda e caixa, migração do banco anterior, isolamento entre contas, recorrência e rollback, confirmação pública, disputa de vagas, recuperação de senha, segundo fator, mensagens sem duplicação, webhook Pix e restauração de backup. Integrações externas são simuladas; nenhum envio ou pagamento real é feito nos testes. O GitHub Actions executa a suíte em cada push/PR.

## Produção e atualização

```bash
export DATABASE='/data/psi.db'
export COOKIE_SECURE=1
export TZ=America/Sao_Paulo
# Configure SECRET_KEY e os demais segredos fora do repositório.
gunicorn --bind 0.0.0.0:8000 --workers 2 'app:create_app()'
```

Use HTTPS, volume persistente criptografado com acesso restrito e backups agendados. As migrações preservam os registros da primeira versão; faça backup antes de atualizar. SQLite atende uma instalação pequena em uma única máquina. Múltiplas instâncias exigem evolução para um banco compartilhado e revisão dos jobs.

Consulte [o guia de operação](docs/OPERACAO.md) para configurar SMTP, WhatsApp, Mercado Pago, cron, backups, restauração e tratamento de dados pessoais. Há uma conta recebedora Pix por instalação; outras contas usam o financeiro manual. Não há prontuários clínicos, notas fiscais, reembolsos parciais automatizados ou gestão de feriados/férias nesta versão.

## Organização do código

- `app.py`: aplicação e fluxos principais.
- `domain.py`: validação, migração e transações de agenda.
- `features.py`: edição, convites, caixa, indicadores, Pix e jobs.
- `security.py`: recuperação, TOTP, backup e restauração.
- `integrations.py`: adaptadores SMTP, Meta e Mercado Pago.
- `templates/`, `static/`: interface.
- `tests/`: testes de integração.

Não versione bancos, backups, dados de pacientes ou segredos. O software precisa ser configurado e validado na sua infraestrutura antes do uso em produção.
