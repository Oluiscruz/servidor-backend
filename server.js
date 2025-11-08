const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

app.use(express.json());

const allowedOrigins = ['https://oluisdev-frontend.netlify.app'];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'],
    credentials: true,
}));

const saltRounds = 10;

const mongoURI = process.env.MONGODB_URI;

// Verifica se a variável de ambiente está definida antes de tentar conectar
if (!mongoURI) {
    console.error('MONGODB_URI não definido. Defina a variável de ambiente MONGODB_URI no painel do Render (Environment > Environment Variables) ou localmente no .env para desenvolvimento.');
    process.exit(1);
}

mongoose.connect(mongoURI)
    .then(() => console.log('Conectado ao MongoDB'))
    .catch(err => {
        console.error('Erro ao conectar ao MongoDB:', err && err.message ? err.message : err);
        console.error('Dica: esse erro normalmente ocorre quando o IP do servidor não está permitido no MongoDB Atlas (Network Access).\n' +
            'No Atlas, abra Network Access -> Add IP Address e adicione o IP do Render ou (temporariamente) 0.0.0.0/0 para permitir acesso.\n' +
            'Documentação: https://www.mongodb.com/docs/atlas/security/ip-access-list/');
    });

const userSchema = new mongoose.Schema({

    nome: {
        type: String,
        required: [true, 'Nome é obrigatório.'],
        minLength: [2, 'O nome deve ter pelo menos 2 caracteres.'],
        trim: true
    },

    email: {
        type: String,
        required: [true, 'Email é obrigatório.'],
        unique: true, //Garante que não tenha emails duplicados
        lowercase: true,
        trim: true
    },
    senha: {
        type: String,
        required: [true, 'Senha é obrigatória.'],
        minLength: [6, 'A senha deve ter pelo menos 6 caracteres.'],
        trim: true
    },

    genero: {
        type: String,
        required: [true, 'Gênero é obrigatório.'],
        trim: true
    },

}, { timestamps: true });

const Usuario = mongoose.model('Usuario', userSchema);

// Rota de cadastro:

app.post('/cadastro', async (req, res) => {
    const { nome, email, senha, genero } = req.body;

    if (!nome || !email || !senha || !genero) {
        return res.status(400).json({ message: 'É obrigatório preencher todos os campos marcados com (*) ' });
    }

    try {
        const existeUsuario = await Usuario.findOne({ email: email });
        if (existeUsuario) {
            return res.status(409).json({ message: 'Email já cadastrado.' });
        }

        const senhaHash = await bcrypt.hash(senha, saltRounds);

        const novoUsuario = new Usuario({ nome: nome, email: email, senha: senhaHash, genero: genero });
        await novoUsuario.save();

        res.status(201).json({
            message: 'Usuário cadastrado com sucesso.',
            user: { nome: novoUsuario.nome, email: novoUsuario.email, genero: novoUsuario.genero }
        });


    }

    catch (error) {
        console.error('Erro ao cadastrar usuário', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: error.message });
        }
        res.status(500).json({ message: 'Erro interno do servidor.' });

    }
});

// Rota de login:

app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ message: 'É obrigatório preencher todos os campos!' });
    }

    try {
        const existeUsuario = await Usuario.findOne({ email: email });

        if (!existeUsuario) {
            return res.status(401).json({ message: 'Email ou senha inválidos.' });
        }

        const senhaValida = await bcrypt.compare(senha, existeUsuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ message: 'Email ou senha inválidos.' });
        }

        res.status(200).json({
            message: `Login realizado com sucesso, bem vindo(a) ${existeUsuario.nome}`,
            user: {
                nome: existeUsuario.nome,
                email: existeUsuario.email,
                genero: existeUsuario.genero
            }
        });
    }

    catch (error) {
        console.error('Erro ao fazer login', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Rota para enviar email
app.post('/enviar-mensagem', async (req, res) => {
    const { nome, email, mensagem, assunto } = req.body;

    if (!nome || !email || !mensagem) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    const mailOptions = {
        from: email,
        to: process.env.EMAIL_USER,
        subject: `${assunto} - ${nome}`,
        text: `
            Nome: ${nome}
            Email: ${email}
            Mensagem: ${mensagem}
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Mensagem enviada com sucesso!' });
    } catch (error) {
        console.error('Erro ao enviar email:', error);
        res.status(500).json({ message: 'Erro ao enviar mensagem.' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

