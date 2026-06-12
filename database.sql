-- 1. Criação da Tabela de Usuários 
CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    cpf VARCHAR(14) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    token_recuperacao TEXT,
    expiracao_token TIMESTAMP
);

-- 2. Criação da Tabela de Sessões (Persistência de Login)
CREATE TABLE "session" (
  "sid" varchar NOT NULL COLLATE "default",
  "sess" json NOT NULL,
  "expire" timestamp(6) NOT NULL,
  CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE
);
CREATE INDEX "IDX_session_expire" ON "session" ("expire");

-- 3. Criação da Tabela de Pedidos 
CREATE TABLE pedidos (
    id SERIAL PRIMARY KEY,
    plano VARCHAR(50) NOT NULL,
    nome_cliente VARCHAR(100) NOT NULL,
    email_cliente VARCHAR(100) NOT NULL,
    cartao VARCHAR(4) NOT NULL,
    nome_cartao VARCHAR(100) NOT NULL,
    data_pedido TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    usuario_id INTEGER,
    CONSTRAINT fk_usuario_pedido 
        FOREIGN KEY (usuario_id) 
        REFERENCES usuarios(id) 
        ON DELETE SET NULL
);

-- 4. Script para promover um usuário a admin (necessário criar o usuário no site ANTES de rodar)
UPDATE usuarios SET is_admin = TRUE WHERE email = 'email de admin aqui';