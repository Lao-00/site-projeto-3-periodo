# Base 5 Automações

Projeto acadêmico que simula o site institucional e o sistema de gestão de uma empresa fictícia de automação financeira. O projeto evoluiu de uma interface estática para uma aplicação Full-Stack com renderização no servidor (SSR), autenticação segura e integração com banco de dados relacional.

---

## 🚀 Tecnologias Utilizadas

- **Backend:** Node.js, Express.js
- **Frontend:** EJS (Template Engine), HTML5, CSS3 (Puro)
- **Banco de Dados:** PostgreSQL
- **Segurança & Sessão:** `bcrypt` (hash de senhas), `express-session` + `connect-pg-simple` (persistência no banco) e `express-rate-limit`
- **Serviços:** `nodemailer` (disparo de e-mails via Gmail SMTP)

---

## 📄 Rotas e Telas

| Rota / Tela        | Descrição                                       |
| ------------------ | ----------------------------------------------- |
| `/` (Index)        | Página inicial                                  |
| `/sobre`           | Página institucional com detalhes das soluções  |
| `/projetos`        | Cases de sucesso e métricas da empresa          |
| `/acessibilidade`  | Declaração de acessibilidade                    |
| `/login`           | Autenticação de usuários                        |
| `/cadastro`        | Criação de novas contas com login automático    |
| `/perfil`          | Área restrita com dados do usuário logado       |
| `/pedidos`         | Painel de listagem de compras (Admin/Cliente)   |
| `/comprar`         | Fluxo de contratação de planos seguro           |
| `/recuperar-senha` | Fluxo de envio de e-mail e redefinição de senha |
| `/alterar-info`    | Atualização de e-mail/senha com validação 2FA   |

---

## 🗂️ Estrutura de Arquivos (Visão Geral)

```text
├── server.js                   # Ponto de entrada do backend, middlewares e rotas
├── .env                        # Variáveis de ambiente (DB, SMTP, Secrets)
├── public/                     # Arquivos estáticos servidos publicamente
│   ├── css/style.css
│   └── imgs/
├── views/                      # Telas renderizadas no servidor (EJS)
│   ├── partials/               # Componentes reaproveitáveis (navbar, footer)
│   ├── index.ejs
│   ├── login.ejs
│   ├── cadastro.ejs
│   └── ...
├── README.md                   # Documentação principal
├── ACESSIBILIDADE.md           # Detalhes das implementações WCAG
└── ARQUITETURA_E_REQUISITOS.md # Detalhes do sistema, segurança e DB
```

---

## 🏗️ Arquitetura e Segurança

O sistema agora conta com um backend robusto protegido contra vulnerabilidades comuns:

- **Rate Limiting:** Bloqueio de ataques de força bruta nas rotas de autenticação.
- **Persistência de Sessão:** Sessões gerenciadas e validadas diretamente no PostgreSQL, garantindo estabilidade mesmo se o servidor for reiniciado.
- **Proteção de Dados Sensíveis:** O CVV e a Validade do cartão de crédito não são armazenados; apenas os últimos 4 dígitos são salvos para fins de histórico.
- **Controle de Acesso (RBAC):** Diferenciação de interface e permissões baseada no status de Administrador (`is_admin`).

Para um detalhamento técnico completo, diagramas e regras de negócio, consulte o documento de [Arquitetura e Requisitos](./ARQUITETURA_E_REQUISITOS.md).

---

## ♿ Acessibilidade (WCAG 2.2 Nível AA)

A interface visual continua seguindo rigorosos padrões de acessibilidade para garantir inclusão:

- **Navegação por Teclado & Skip Link:** Fluxo totalmente operável via `Tab` e `Enter`, com foco visível customizado (`:focus-visible`).
- **Semântica e ARIA:** Uso correto de tags estruturais e atributos `aria-` para total suporte a leitores de tela.
- **Contraste & Responsividade:** Cores validadas e layout fluido e adaptável a qualquer dispositivo.
- **VLibras:** Ferramenta governamental integrada para tradução do conteúdo para a Língua Brasileira de Sinais.

Para visualizar todos os critérios técnicos implementados e validados, consulte a nossa [Declaração de Acessibilidade](./ACESSIBILIDADE.md).
