# PsiSaas

Aplicação web em português para organizar consultórios de psicologia. Primeira versão funcional com Flask, SQLite e interface responsiva, sem serviços pagos obrigatórios.

## O que funciona

- Login com senha protegida por hash, limite de tentativas e sessão de 8 horas.
- Dados separados por profissional: cada conta acessa somente seus pacientes e sessões.
- Cadastro e busca de pacientes, contatos e lista de espera.
- Agendamento presencial ou online, duração e valor; bloqueio de horários sobrepostos.
- Confirmação manual, registro de realização, falta e cancelamento.
- Painel diário e financeiro por mês de atendimento; baixa e estorno manual de pagamentos.
- Exportação do histórico financeiro em CSV.
- Mensagens de lembrete e cobrança abertas no WhatsApp para revisão e envio manual.

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

Abra http://127.0.0.1:5000 e entre com a conta criada. A senha precisa ter pelo menos 12 caracteres. O comando `create-user` pode ser repetido para cadastrar outros profissionais. Não há usuários ou senhas padrão, nem dados fictícios pré-carregados.

No Windows, use `.venv\Scripts\Activate.ps1` e defina a variável com `$env:SECRET_KEY`. Mantenha a mesma chave ao reiniciar o serviço; gere-a uma vez e guarde-a no gerenciador de segredos da hospedagem.

## Testar

```bash
python -m unittest discover -s tests -v
```

Os testes usam bancos temporários: verificam agendamento, conflitos, cancelamentos, pagamentos, lista de espera, isolamento entre contas, CSRF, validação de valores, escape HTML, CSV e limite de login.

## Hospedagem

```bash
export SECRET_KEY='segredo-longo-gerado-fora-do-repositorio'
export DATABASE='/data/psi.db'
export COOKIE_SECURE=1
gunicorn --bind 0.0.0.0:8000 --workers 2 'app:create_app()'
```

Use HTTPS em um proxy reverso, volume persistente em `/data` com permissões restritas e backups criptografados. Crie as contas pelo CLI no mesmo ambiente. `COOKIE_SECURE=1` exige HTTPS; não use essa opção no teste local por HTTP. O SQLite é adequado para uma instalação pequena em uma única máquina; para múltiplas instâncias, migre para PostgreSQL e um serviço compartilhado de limitação de login.

## Escopo e próximos passos

Esta versão administra agenda, contatos e valores. Não armazena prontuários ou anotações clínicas. Não inclui cobrança bancária, emissão fiscal, recorrência, recuperação de senha por e-mail nem mensagens automáticas. Alterar data, paciente ou valor de uma sessão exige cancelar a sessão e agendar novamente; dados de pacientes não têm edição/exclusão pela interface nesta versão.

Os relatórios seguem o mês da sessão, não a data em que o dinheiro entrou. Sessões canceladas ficam fora dos totais e exigem estorno manual antes do cancelamento. Os horários usam a hora local do consultório; configure o fuso do servidor de acordo com a instalação.

Antes de operar com dados reais, configure hospedagem e backups seguros, política de retenção, procedimentos de acesso/correção/exclusão e termos adequados à operação. O banco não tem criptografia própria em repouso; use disco/volume criptografado. A aplicação não representa certificação ou garantia de conformidade com a LGPD.

## Estrutura

- `app.py`: autenticação, banco, validações e rotas.
- `templates/`: telas renderizadas no servidor, com escape automático.
- `static/style.css`: visual responsivo sem CDN.
- `tests/`: testes de integração.
- `.github/workflows/tests.yml`: execução dos testes no GitHub Actions.

Nenhum dado de paciente, banco de dados ou segredo deve ser versionado.
