require('dotenv').config(); // Importa e configura o dotenv
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const pgSession = require('connect-pg-simple')(session);
const app = express();

// Configuração do banco de dados puxando do arquivo .env
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000, // Espera no máximo 5 segundos para conectar
    query_timeout: 5000, // Espera no máximo 5 segundos para uma query rodar
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

app.use(
    session({
        store: new pgSession({
            pool: pool,
            tableName: 'session',
        }),
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false,
            maxAge: 5 * 60 * 60 * 1000, // 5 horas em milissegundos
        },
    })
);

// Middleware para disponibilizar o usuário para todas as telas (EJS)
app.use((req, res, next) => {
    res.locals.usuario = req.session.usuario || null;
    next();
});

// Função de segurança para bloquear páginas restritas
const verificarLogin = (req, res, next) => {
    if (req.session.usuario) {
        next();
    } else {
        res.redirect('/login?aviso=restrito');
    }
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// =======================================================================
// MODO DE MANUTENÇÃO (Erro 503)
// =======================================================================
const emManutencao = false; // Quando precisar atualizar  o banco de dados, mude para 'true'

app.use((req, res, next) => {
    if (emManutencao) {
        res.status(503).render('erro503');
    } else {
        next(); // Se não estiver em manutenção, deixa o site funcionar normal
    }
});
// =======================================================================

// Configuração do Limite de Requisições (Erro 429)
const rateLimit = require('express-rate-limit');
const limitadorGeral = rateLimit({
    windowMs: 1 * 60 * 1000, // Janela de tempo: 1 minuto (em milissegundos)
    max: 5, // Limite: bloqueia no 6º acesso dentro do mesmo minuto
    handler: (req, res) => {
        res.status(429).render('erro429');
    },
});
app.use('/login', limitadorGeral);
app.use('/cadastro', limitadorGeral);
app.use('/comprar', limitadorGeral);

// ROTAS DE TELAS
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/acessibilidade', (req, res) => {
    res.render('acessibilidade');
});

app.get('/sobre', (req, res) => {
    res.render('sobre');
});

app.get('/projetos', (req, res) => {
    res.render('projetos');
});

app.get('/login', (req, res) => {
    const avisoUrl = req.query.aviso;
    res.render('login', { aviso: avisoUrl });
});

app.get('/perfil', verificarLogin, async (req, res) => {
    try {
        // 1. Pega o ID do usuário que está salvo na sessão
        const usuarioId = req.session.usuario.id;

        // 2. Busca os dados completos do usuário no banco de dados
        const usuarioQuery = await pool.query(
            'SELECT nome, email, cpf FROM usuarios WHERE id = $1',
            [usuarioId]
        );

        // Se por algum motivo o usuário não for encontrado no banco
        if (usuarioQuery.rows.length === 0) {
            return res.redirect('/logout');
        }

        const dadosUsuario = usuarioQuery.rows[0];

        // 3. Renderiza a página enviando APENAS os dados do usuário
        res.render('perfil', {
            dados: dadosUsuario,
        });
    } catch (err) {
        console.error('Erro ao carregar perfil:', err);
        res.status(500).render('erro500');
    }
});

app.get('/cadastro', (req, res) => {
    const avisoUrl = req.query.aviso;
    res.render('cadastro', { aviso: avisoUrl });
});

app.get('/comprar', verificarLogin, (req, res) => {
    const planoEscolhido = req.query.plano || 'Nenhum plano selecionado';
    res.render('comprar', { plano: planoEscolhido });
});

app.get('/recuperar-senha', (req, res) => {
    res.render('recuperar-senha', {
        etapa: 'solicitar',
        aviso: req.query.aviso || null,
    });
});

// ============================================
// RECUPERAÇÃO DE SENHA
//============================================

// ROTA GET: Abre a tela de digitar a nova senha (vinda do clique no e-mail)
app.get('/resetar-senha', async (req, res) => {
    const { token } = req.query;

    try {
        // Busca se existe o token e se ele ainda não expirou (NOW() verifica a hora atual do banco)
        const sql =
            'SELECT id FROM usuarios WHERE token_recuperacao = $1 AND expiracao_token > NOW()';
        const result = await pool.query(sql, [token]);

        if (result.rows.length === 0) {
            return res.status(400).send('Este link de recuperação é inválido ou já expirou.');
        }

        // Se o token for válido, renderiza a tela passando o token para o formulário
        res.render('recuperar-senha', { etapa: 'resetar', token: token });
    } catch (err) {
        console.error(err);
        res.status(500).render('erro500');
    }
});

// ROTA POST: Recebe a nova senha e salva por cima da antiga
app.post('/resetar-senha', async (req, res) => {
    const { token, senha } = req.body;

    try {
        // Criptografa a nova senha antes de salvar
        const senhaHash = await bcrypt.hash(senha, 10);

        // Atualiza a senha e APAGA o token do banco para ele não ser reutilizado
        const sql = `
            UPDATE usuarios 
            SET senha = $1, token_recuperacao = NULL, expiracao_token = NULL 
            WHERE token_recuperacao = $2
        `;

        await pool.query(sql, [senhaHash, token]);

        // Redireciona para o login avisando que mudou com sucesso
        res.redirect('/login?aviso=senha_alterada');
    } catch (err) {
        console.error(err);
        res.status(500).render('erro500');
    }
});
// ============================================
// ============================================

// ============================================
// ALTERAÇÃO DE DADOS (PERFIL)
// ============================================

// 1. Renderiza a tela inicial de escolha ou o formulário selecionado
app.get('/alterar-info', verificarLogin, (req, res) => {
    const tipo = req.query.tipo; // Pega o ?tipo= da URL

    // Se o usuário já escolheu o que alterar, manda para a tela do input
    if (tipo === 'email' || tipo === 'senha') {
        res.render('alterar-info', { etapa: 'formulario', tipoAlteracao: tipo, aviso: null });
    } else {
        // Se não, mostra a tela inicial com os dois botões
        res.render('alterar-info', { etapa: 'escolha', aviso: null });
    }
});

// 2. Recebe o que ele quer mudar, gera o código e envia o e-mail
app.post('/alterar-info/solicitar', verificarLogin, async (req, res) => {
    const { tipoAlteracao, novoValor } = req.body;
    const usuarioId = req.session.usuario.id;

    try {
        // Busca o email atual do usuário no banco para saber pra onde enviar o código
        const userQuery = await pool.query('SELECT email FROM usuarios WHERE id = $1', [usuarioId]);
        const emailAtual = userQuery.rows[0].email;

        // Gera um código numérico de 6 dígitos (ex: 482910)
        const codigo = Math.floor(100000 + Math.random() * 900000).toString();
        const expiracao = new Date(Date.now() + 900000); // 15 minutos

        // Salva o código no banco
        await pool.query(
            'UPDATE usuarios SET token_recuperacao = $1, expiracao_token = $2 WHERE id = $3',
            [codigo, expiracao, usuarioId]
        );

        // Monta e dispara o e-mail
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: emailAtual,
            subject: 'Base 5 - Código de Segurança',
            html: `
                <h3>Código de Confirmação</h3>
                <p>Você solicitou a alteração de <b>${tipoAlteracao}</b> na Base 5 Automações.</p>
                <p>Seu código de segurança é: <strong style="font-size: 24px; color: #1a56db;">${codigo}</strong></p>
                <p>Este código expira em 15 minutos. Se não foi você quem solicitou, ignore este e-mail.</p>
            `,
        };
        await transporter.sendMail(mailOptions);

        // Manda o usuário para a etapa de digitar o código, passando o que ele quer alterar pra frente
        res.render('alterar-info', {
            etapa: 'confirmar',
            tipoAlteracao,
            novoValor,
            aviso: null,
        });
    } catch (err) {
        console.error('Erro ao solicitar alteração:', err);
        res.status(500).render('erro500');
    }
});

// 3. Verifica se o código tá certo e salva a alteração no banco
app.post('/alterar-info/confirmar', verificarLogin, async (req, res) => {
    // Esses 3 campos vêm do formulário escondido (hidden) + input do código
    const { codigo, tipoAlteracao, novoValor } = req.body;
    const usuarioId = req.session.usuario.id;

    try {
        // Verifica se o código bate com o do banco e se não passou de 15 minutos
        const result = await pool.query(
            'SELECT id FROM usuarios WHERE id = $1 AND token_recuperacao = $2 AND expiracao_token > NOW()',
            [usuarioId, codigo]
        );

        // Se o código for errado ou estiver expirado, devolve pra tela com aviso
        if (result.rows.length === 0) {
            return res.render('alterar-info', {
                etapa: 'confirmar',
                tipoAlteracao,
                novoValor,
                aviso: 'Código inválido ou expirado! Verifique seu e-mail novamente.',
            });
        }

        // Se o código passou, executamos a alteração de fato!
        if (tipoAlteracao === 'senha') {
            const senhaHash = await bcrypt.hash(novoValor, 10); // Criptografa a nova senha
            await pool.query(
                'UPDATE usuarios SET senha = $1, token_recuperacao = NULL, expiracao_token = NULL WHERE id = $2',
                [senhaHash, usuarioId]
            );
        } else if (tipoAlteracao === 'email') {
            await pool.query(
                'UPDATE usuarios SET email = $1, token_recuperacao = NULL, expiracao_token = NULL WHERE id = $2',
                [novoValor, usuarioId]
            );
        }

        // Exibe a telinha de sucesso
        res.render('alterar-info', { etapa: 'sucesso', aviso: null });
    } catch (err) {
        // Tratamento caso ele tente alterar para um e-mail que já existe no banco
        if (err.code === '23505' && err.constraint.includes('email')) {
            return res.render('alterar-info', {
                etapa: 'escolha',
                aviso: 'Este e-mail já está em uso por outra conta.',
            });
        }
        console.error('Erro ao confirmar alteração:', err);
        res.status(500).render('erro500');
    }
});

// ============================================
// ============================================

// ROTA DE CADASTRO
app.post('/cadastro', async (req, res) => {
    const { nome, cpf, email, senha } = req.body;
    try {
        const senhaHash = await bcrypt.hash(senha, 10); // Embaralha a senha
        const query =
            'INSERT INTO usuarios (nome, cpf, email, senha) VALUES ($1, $2, $3, $4) RETURNING id, nome';
        const result = await pool.query(query, [nome, cpf, email, senhaHash]);

        // Loga o usuário automaticamente após cadastrar
        req.session.usuario = result.rows[0];
        res.redirect('/');
    } catch (err) {
        // Verifica se o erro no PostgreSQL é de dado duplicado (código 23505)
        if (err.code === '23505') {
            // Verifica se a restrição violada tem a palavra 'email' no nome
            if (err.constraint.includes('email')) {
                return res.redirect('/cadastro?aviso=email_duplicado');
            }

            // Verifica se a restrição violada tem a palavra 'cpf' no nome
            if (err.constraint.includes('cpf')) {
                return res.redirect('/cadastro?aviso=cpf_duplicado');
            }
        }

        // Se não for dado duplicado, então é um erro crítico genérico
        console.error('Erro crítico no cadastro:', err);
        res.status(500).render('erro500');
    }
});

// ROTA DE LOGIN
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            const usuario = result.rows[0];
            const senhaValida = await bcrypt.compare(senha, usuario.senha);
            if (senhaValida) {
                req.session.usuario = {
                    id: usuario.id,
                    nome: usuario.nome,
                    is_admin: usuario.is_admin,
                };
                return res.redirect('/');
            }
        }
        // Redirecionamento com aviso
        res.redirect('/login?aviso=invalido');
    } catch (err) {
        console.error('Erro crítico', err);
        res.status(500).render('erro500');
    }
});

// ROTA DE LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ROTA RECUPERAR SENHA
app.post('/recuperar-senha', async (req, res) => {
    const { email } = req.body; // extrai o email informado

    try {
        // 1. Verifica se o e-mail existe no banco
        const result = await pool.query('SELECT id, nome FROM usuarios WHERE email = $1', [email]); //pega id e nome do email informado

        if (result.rows.length === 0) {
            // Se o e-mail não existir no banco, devolve para a tela com o aviso
            return res.redirect('/recuperar-senha?aviso=nao_encontrado');
        }
        const usuario = result.rows[0]; //pega o primeiro item e armazena como usuário

        // 2. Gera o Token e a data de expiração (15 min)
        const token = crypto.randomBytes(20).toString('hex'); //gera 20 bytes aleatório e então o transforma em hex
        const expiracao = new Date(Date.now() + 900000); // Exatamente 15 minutos quando gerado

        // 3. Salva no banco de dados
        await pool.query(
            'UPDATE usuarios SET token_recuperacao = $1, expiracao_token = $2 WHERE id = $3',
            [token, expiracao, usuario.id]
        );

        // 4. Monta o e-mail
        const linkReset = `http://localhost:3000/resetar-senha?token=${token}`; //injeta o código direto na url

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Base 5 - Recuperação de Senha',
            html: `
                <h3>Olá, ${usuario.nome}</h3>
                <p>Você solicitou a recuperação de senha da sua conta na Base 5.</p>
                <p>Clique no link abaixo para criar uma nova senha. <b>Este link expira em 15 minutos.</b></p>
                <a href="${linkReset}">Redefinir minha senha</a>
                <p>Se você não solicitou isso, ignore este e-mail.</p>
            `,
        };

        // 5. Dispara o e-mail
        await transporter.sendMail(mailOptions);

        // 6. Avisa o usuário que deu certo
        res.render('recuperar-senha', { etapa: 'aviso' });
    } catch (err) {
        console.error('Erro na recuperação:', err);
        res.status(500).render('erro500');
    }
});

// ROTA DE COMPRA (Vinculando ao usuário e salvando apenas o final do cartão para segurança)
app.post('/comprar', verificarLogin, async (req, res) => {
    // Extrai todos os campos do formulário
    const { plano, nome, email, cartao, validade, cvv, nomeCartao } = req.body;

    console.log('PLANO QUE CHEGOU DO HTML: ->', plano, '<-');
    // =======================================================================
    // VALIDAÇÃO DE SEGURANÇA (Erro 400 - Bad Request)
    // =======================================================================
    const planosValidos = ['Basico', 'Profissional', 'Enterprise'];

    // Se o plano estiver vazio ou não for um dos três planos oficiais:
    if (!plano || !planosValidos.includes(plano)) {
        return res.status(400).render('erro400');
    }
    // =======================================================================

    // Pega o ID se estiver logado
    const usuarioId = req.session.usuario ? req.session.usuario.id : null;

    try {
        // Extrai apenas os últimos 4 dígitos do número do cartão recebido
        const ultimos4Digitos = cartao.replace(/\s/g, '').slice(-4);

        // Não envia os dados de validade e cvv
        const query = `
            INSERT INTO pedidos 
            (plano, nome_cliente, email_cliente, usuario_id, cartao, nome_cartao) 
            VALUES ($1, $2, $3, $4, $5, $6)
        `;

        // Executa a query passando os parâmetros corretos sem validade e cvv
        await pool.query(query, [plano, nome, email, usuarioId, ultimos4Digitos, nomeCartao]);

        // Renderiza a tela passando a variável sucesso como TRUE
        res.render('resultado', { sucesso: true });
    } catch (err) {
        console.error(err);

        // Renderiza a página global de erro 500, passando a mensagem específica do pedido
        res.status(500).render('erro500', {
            mensagem:
                'Não foi possível processar seu pedido no momento. Tente novamente mais tarde.',
        });
    }
});

app.get('/pedidos', verificarLogin, async (req, res) => {
    const { id, is_admin } = req.session.usuario;
    try {
        let sql;
        let params = [];

        if (is_admin) {
            // Admin vê tudo de todas as colunas
            sql = 'SELECT * FROM pedidos ORDER BY data_pedido DESC';
        } else {
            // Usuário comum vê só o dele
            sql = 'SELECT * FROM pedidos WHERE usuario_id = $1 ORDER BY data_pedido DESC';
            params = [id];
        }

        const result = await pool.query(sql, params);
        res.render('pedidos', { listaPedidos: result.rows, eAdmin: is_admin });
    } catch (err) {
        console.error(err);
        res.status(500).render('erro500');
    }
});

// ROTA 404 (Página Não Encontrada) - Deve ser sempre a última rota do arquivo!
app.use((req, res) => {
    res.status(404).render('erro404');
});

// Iniciar o servidor
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
