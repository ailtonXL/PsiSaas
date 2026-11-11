# Operação, integrações e dados pessoais

## Atualizar a instalação anterior

1. Pare o serviço e faça uma cópia segura do banco atual e das variáveis de ambiente.
2. Instale `requirements.txt` e mantenha `SECRET_KEY` e `DATABASE` da instalação.
3. Inicie a aplicação. A migração adiciona colunas e tabelas preservando pacientes e sessões. Inicializações seguintes não repetem as alterações.
4. Confira usuários, sessões e financeiro. Pagamentos antigos sem data permanecem sem data; use **Corrigir data** no financeiro. Eles ficam fora do caixa até a correção.

Configure `TZ` no processo/contêiner para o fuso do consultório. Os horários de agenda continuam locais, sem conversão por navegador. Use uma instalação por fuso.

## Segredos e HTTPS

Defina `PUBLIC_BASE_URL` com o domínio HTTPS oficial e `COOKIE_SECURE=1` em produção. O endereço público é necessário para links de confirmação, recuperação, convites e webhook. Nunca use o cabeçalho Host fornecido pelo visitante para gerar links enviados por e-mail.

Gere chaves independentes:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Use respectivamente para `SECRET_KEY`, `MFA_KEY` e `BACKUP_KEY`. Não salve os resultados no Git. As duas últimas chaves não são intercambiáveis. Preserve a chave MFA ao restaurar um backup. A perda dela impede validar os autenticadores cadastrados.

## Lembretes automáticos

O profissional precisa marcar a autorização do paciente no cadastro/edição. A autorização começa desmarcada, inclusive para pacientes existentes. Registre a base legal e a evidência da autorização de acordo com a operação.

- Configure SMTP com STARTTLS, usuário, senha e remetente para e-mail.
- Para WhatsApp, configure a Cloud API oficial da Meta: `WA_PHONE_ID`, `WA_ACCESS_TOKEN` e `WA_TEMPLATE`. O template aprovado deve ter três parâmetros de corpo, na ordem: rótulo neutro do agendamento, data/horário e URL completa de confirmação. Idioma `pt_BR`.
- Quando WhatsApp está configurado e há telefone, esse canal tem preferência; caso contrário, usa e-mail se disponível. Falha em WhatsApp não dispara e-mail adicional automaticamente.
- Agende `flask --app 'app:create_app()' send-reminders` a cada cinco minutos, no mesmo ambiente e banco da aplicação.

Exemplo de crontab (ajuste caminhos e carregue as variáveis de ambiente por um arquivo protegido ou serviço):

```cron
*/5 * * * * cd /srv/PsiSaas && .venv/bin/flask --app 'app:create_app()' send-reminders >> /var/log/psisaas-jobs.log 2>&1
0 3 * * * cd /srv/PsiSaas && .venv/bin/flask --app 'app:create_app()' backup /backups/psi-$(date +\%Y\%m\%d-\%H\%M\%S).enc >> /var/log/psisaas-jobs.log 2>&1
```

O comando seleciona sessões agendadas/confirmadas nas próximas 24 horas e registra cada tentativa por sessão, horário e canal para evitar duplicatas entre execuções. Um resultado incerto não é reenviado automaticamente. Confira `reminder-status` e o provedor; se a mensagem não tiver sido entregue, use `retry-reminder ID` para liberar nova tentativa. Se o serviço ficar fora do ar até passar o horário, não há envio retroativo.

Os links de presença duram até sete dias, deixam de funcionar quando o horário passa, a sessão é cancelada ou reagendada. Abrir o link não confirma: o paciente precisa pressionar o botão. O link contém uma autorização temporária; compartilhe somente com o destinatário.

## Lista de espera

Após cancelar uma sessão futura, use **Oferecer à lista de espera**. Escolha o paciente e compartilhe o convite gerado. O convite mostra horário, modalidade e valor, expira em até 24 horas e requer aceite. O primeiro aceite ocupa o horário em uma transação; os demais convites para a vaga são encerrados. Não há disparo em massa para toda a lista.

## Pix Mercado Pago

1. Use uma conta Mercado Pago habilitada para Pix e obtenha credenciais de teste/produção no painel oficial.
2. Defina `MP_ACCESS_TOKEN`, `MP_WEBHOOK_SECRET` e `MP_OWNER_EMAIL`. O e-mail deve coincidir com a conta do profissional no PsiSaas.
3. Cadastre a URL `https://SEU-DOMINIO/webhooks/mercadopago` para notificações de pagamento.
4. No financeiro, use **Emitir Pix**. O paciente precisa ter e-mail cadastrado. A tela fornece o código copia e cola.
5. A baixa automática só ocorre depois da assinatura válida do webhook e de uma consulta autenticada à API, verificando referência da sessão, conta, identificador, moeda BRL e valor. Repetições do webhook não duplicam o recebimento. A tela permite consultar e conciliar manualmente.

A chave de idempotência é persistida antes da chamada de emissão. Se houver timeout, repita a emissão para consultar/criar a mesma cobrança. Não altere essa chave diretamente no banco.

Enquanto houver cobrança ativa ou emissão pendente, edição/cancelamento e baixa manual ficam bloqueados. Faça estorno ou cancelamento bancário no Mercado Pago, consulte a cobrança no PsiSaas e **Desvincule a cobrança encerrada**. Reembolsos parciais não têm rateio nesta versão; devem ser conciliados administrativamente antes de usar os totais como fechamento contábil.

**Limite:** há uma conta recebedora por instalação. Outros profissionais continuam usando controle manual; não recebem Pix na conta de terceiros. A distribuição para várias contas exige OAuth e gestão individual das credenciais, ainda não implementados.

Os testes automatizados usam respostas simuladas, sem movimentar dinheiro ou enviar mensagens. Antes de ativar produção, valide emissão, pagamento, repetição de webhook e estorno no ambiente disponibilizado pelo provedor.

## Recuperação de senha e autenticação em duas etapas

A recuperação depende do SMTP e de `PUBLIC_BASE_URL`. O link expira em 30 minutos, funciona uma vez e invalida sessões abertas ao trocar a senha. A resposta de solicitação não revela se o e-mail existe. Recuperar senha não remove o segundo fator.

Em **Minha conta**, configure o autenticador com uma chave TOTP manual. Os códigos têm seis dígitos e intervalos de 30 segundos, com tolerância de um intervalo. O servidor deve ter o relógio sincronizado. Segredos TOTP são criptografados no banco com `MFA_KEY`; códigos já utilizados são rejeitados. Ativar/desativar exige a senha; desativar também exige o código. Novas configurações não substituem um fator ativo sem desativá-lo primeiro.

Se o profissional perder o autenticador, o administrador precisa verificar sua identidade por um procedimento externo antes de executar:

```bash
flask --app 'app:create_app()' disable-mfa --email profissional@example.com
```

O comando pede confirmação, remove o fator e invalida sessões. Evite executá-lo como procedimento automático de suporte.

## Backups e restauração

```bash
flask --app 'app:create_app()' backup /backups/psi-2026-11-11.enc
flask --app 'app:create_app()' restore-backup /backups/psi-2026-11-11.enc /data/psi-restaurado.db
```

O backup usa o mecanismo de snapshot consistente do SQLite e criptografia autenticada Fernet, com arquivo de permissão 0600. A restauração exige um destino novo, autentica o conteúdo e verifica a integridade do banco. Não sobrescreve um banco em uso.

Para recuperar produção: pare a aplicação, restaure em novo arquivo, confira os dados, selecione o novo caminho `DATABASE` e reinicie com as mesmas chaves e variáveis. Preserve a cópia anterior até concluir a verificação. Não rode restaurações enquanto o serviço está gravando no arquivo que você pretende substituir.

Um teste automatizado cria registros, gera backup, restaura e verifica o conteúdo e a integridade. O operador deve repetir esse exercício periodicamente na infraestrutura real, verificar o agendamento e manter cópias em local separado. Sugestão inicial de retenção operacional: 30 backups diários; o prazo final deve seguir a política da organização. Os comandos não apagam backups antigos automaticamente.

## Solicitações de dados e exclusão

Na edição do paciente, use a exportação JSON para reunir cadastro e sessões. A exclusão exige digitar EXCLUIR e remove cadastro, sessões, tentativas de lembrete e convites relacionados. Isso altera também os totais históricos. Cobranças Pix devem ser resolvidas e desvinculadas antes.

Defina quem aprova exclusões e quais registros precisam ser preservados por obrigação legal/contratual. A exclusão não apaga registros de provedores ou backups existentes: aplique as políticas e prazos correspondentes nesses locais. Depois de restaurar um backup, reaplique exclusões legítimas realizadas após a data do snapshot, usando um registro operacional protegido das solicitações.

A aplicação não armazena prontuários clínicos e não garante, isoladamente, conformidade com a LGPD. Use armazenamento criptografado, HTTPS, acesso restrito ao servidor/banco, revisão periódica de acessos e aviso de privacidade adequado ao serviço.

## Indicadores e caixa

O caixa usa a data efetiva de recebimento; despesas usam a data informada. O resultado é recebimentos menos despesas, não lucro contábil certificado. Os valores de sessões por competência continuam separados. CSV exporta sessões e datas de recebimento, sem as despesas.

A taxa de faltas considera apenas sessões passadas marcadas como Realizada ou Faltou. Valores em atraso são sessões passadas não pagas. Defina dias e horários de trabalho em **Indicadores → Definir disponibilidade** para calcular a ocupação: minutos reservados dentro do expediente / minutos disponíveis no mês. Feriados e férias não são descontados automaticamente; a definição não bloqueia agendamentos fora do expediente.
