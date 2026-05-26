# Arquitetura e Requisitos Implementados

## 1. Arquitetura do Sistema

- **Backend:** Node.js com Express.js
- **Frontend (Views):** Server-Side Rendering (SSR) utilizando EJS
- **Banco de Dados:** PostgreSQL (acessado via pacote `pg`)
- **Estilização/Assets:** Arquivos estáticos servidos pelo diretório `public/`
- **Gerenciamento de Estado:** Sessões em memória utilizando `express-session`
- **Serviço de Mensageria:** Disparo de e-mails via `nodemailer` utilizando serviço SMTP do Gmail

## 2. Requisitos Funcionais Implementados

### Autenticação e Conta

- **Login:** Autenticação via E-mail e Senha. Middleware de Rate Limit (`express-rate-limit`) configurado especificamente nesta rota para bloquear múltiplas tentativas seguidas (prevenção de força bruta).
- **Cadastro:** Coleta de Nome, CPF, E-mail e Senha. Tratamento direto de erros do banco para CPF e E-mail duplicados. Login automático efetuado em seguida.
- **Recuperação de Senha:**
    - Geração de token via módulo nativo `crypto` com tempo de expiração de 15 minutos.
    - Envio do link contendo o token via e-mail.
    - Rota de verificação do token e definição de nova senha, inutilizando o token após o uso.
- **Logout:** Rota para encerramento de sessão via `destroy()`.

### Perfil e Controle de Acesso

- **Níveis de Acesso:** Diferenciação entre visitante, usuário comum e administrador (variável `is_admin`).
- **Página de Perfil:** Rota restrita exibindo dados (Nome, CPF, E-mail) extraídos do banco de dados correspondentes ao ID logado.
- **Middlewares Globais:** Proteção de rotas fechadas com verificação de login e injeção do usuário nas views (`res.locals.usuario`).

### Sistema de Pedidos

- **Registro de Compra:** Salvamento de plano escolhido e dados sensíveis/fictícios (cartão, validade, cvv) amarrados ao `usuario_id`.
- **Validação:** Checagem restrita de integridade para permitir apenas planos oficialmente aceitos ("Basico", "Profissional", "Enterprise"), retornando Erro 400 em caso de manipulação.
- **Listagem (Painel):**
    - Usuários normais visualizam apenas seu próprio histórico de pedidos.
    - Administradores visualizam todos os pedidos registrados no sistema, ordenados cronologicamente.

## 3. Segurança e Confiabilidade

- **Criptografia:** Senhas armazenadas com hash forte (`bcrypt`).
- **Segurança de Banco:** Parâmetros de queries padronizados (Prepared Statements) contra ataques de Injeção de SQL.
- **Gestão de Exceções (Telas Customizadas):**
    - View Erro 400 (Bad Request).
    - View Erro 404 (Not Found, rota coringa final).
    - View Erro 429 (Too Many Requests no Login).
    - View Erro 500 (Internal Server Error para falhas críticas).
    - View Erro 503 (Manutenção programada via variável de controle global).
