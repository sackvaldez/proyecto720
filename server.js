const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs-extra');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            fontSrc: ["'self'"]
        }
    }
}));

// Rate limiting para prevenir ataques de fuerza bruta
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos por IP
    message: { error: 'Demasiados intentos de login. Intenta de nuevo en 15 minutos.' },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: { error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' }
});

// CORS configuración
app.use(cors({
    origin: false, // Solo permitir mismo origen
    credentials: true
}));

// Rate limiting general
app.use(generalLimiter);

// Configuración de middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'caballero-solutions-power-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS en producción
        httpOnly: true, // Prevenir acceso desde JavaScript
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        sameSite: 'strict' // Protección CSRF
    },
    name: 'sessionId' // Cambiar nombre por defecto
}));

// Función para validar errores
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            message: 'Datos de entrada inválidos',
            errors: errors.array()
        });
    }
    next();
}

// Función para sanitizar nombres de archivo
function sanitizeFilename(filename) {
    return filename.replace(/[^a-zA-Z0-9.-]/g, '_');
}

// Función para validar path traversal
function validatePath(userPath, basePath) {
    const resolvedPath = path.resolve(basePath, userPath);
    return resolvedPath.startsWith(path.resolve(basePath));
}

// Base de datos simulada de clientes (en producción usar una base de datos real)
const clients = {
    'admin': {
        password: bcrypt.hashSync('admin123', 10),
        isAdmin: true,
        name: 'Administrador'
    },
    'cliente1': {
        password: bcrypt.hashSync('pass123', 10),
        isAdmin: false,
        name: 'Cliente Ejemplo 1'
    },
    'cliente2': {
        password: bcrypt.hashSync('pass456', 10),
        isAdmin: false,
        name: 'Cliente Ejemplo 2'
    }
};

// Configuración de multer para subida de archivos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const clientId = req.body.clientId;
        const year = req.body.year;
        const month = req.body.month;
        
        // Validar que los parámetros no contengan caracteres peligrosos
        if (!clientId || !year || !month || 
            !/^[a-zA-Z0-9_-]+$/.test(clientId) ||
            !/^\d{4}$/.test(year) ||
            !/^[a-zA-Z]+$/.test(month)) {
            return cb(new Error('Parámetros de ruta inválidos'), null);
        }
        
        const uploadPath = path.join(__dirname, 'uploads', clientId, year, month);
        
        // Validar que la ruta no escape del directorio base
        if (!validatePath(path.join(clientId, year, month), path.join(__dirname, 'uploads'))) {
            return cb(new Error('Ruta de archivo inválida'), null);
        }
        
        fs.ensureDirSync(uploadPath);
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const timestamp = Date.now();
        const sanitizedName = sanitizeFilename(file.originalname);
        cb(null, `${timestamp}-${sanitizedName}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 200 * 1024 * 1024, // 200MB
        files: 1, // Solo un archivo por vez
        fieldSize: 1024 * 1024 // 1MB para campos de texto
    },
    fileFilter: function (req, file, cb) {
        // Validar tipo MIME
        if (file.mimetype !== 'application/pdf') {
            return cb(new Error('Solo se permiten archivos PDF'), false);
        }
        
        // Validar extensión de archivo
        const allowedExtensions = ['.pdf'];
        const fileExtension = path.extname(file.originalname).toLowerCase();
        if (!allowedExtensions.includes(fileExtension)) {
            return cb(new Error('Extensión de archivo no permitida'), false);
        }
        
        // Validar nombre de archivo
        if (file.originalname.length > 255) {
            return cb(new Error('Nombre de archivo demasiado largo'), false);
        }
        
        cb(null, true);
    }
});

// Middleware de autenticación
function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        next();
    } else {
        res.status(403).send('Acceso denegado');
    }
}

// Rutas
app.get('/', (req, res) => {
    if (req.session.user) {
        if (req.session.user.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/client');
        }
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', 
    loginLimiter,
    [
        body('username')
            .isLength({ min: 1, max: 50 })
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('Usuario debe contener solo letras, números, guiones y guiones bajos'),
        body('password')
            .isLength({ min: 1, max: 100 })
            .withMessage('Contraseña requerida')
    ],
    handleValidationErrors,
    (req, res) => {
        const { username, password } = req.body;
        const client = clients[username];
        
        if (client && bcrypt.compareSync(password, client.password)) {
            req.session.user = {
                username: username,
                name: client.name,
                isAdmin: client.isAdmin
            };
            res.json({ success: true, isAdmin: client.isAdmin });
        } else {
            // No revelar si el usuario existe o no
            res.status(401).json({ success: false, message: 'Credenciales incorrectas' });
        }
    }
);

app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/client', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

app.post('/upload', requireAuth, requireAdmin, upload.single('file'), (req, res) => {
    try {
        res.json({ 
            success: true, 
            message: 'Archivo subido exitosamente',
            filename: req.file.filename
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.get('/api/clients', requireAuth, (req, res) => {
    const clientList = Object.keys(clients)
        .filter(key => !clients[key].isAdmin)
        .map(key => ({ id: key, name: clients[key].name }));
    res.json(clientList);
});

app.get('/api/user', requireAuth, (req, res) => {
    res.json({
        username: req.session.user.username,
        name: req.session.user.name,
        isAdmin: req.session.user.isAdmin
    });
});

// Rutas para gestión de usuarios (solo admin)
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
    try {
        const users = Object.keys(clients).map(username => ({
            username,
            name: clients[username].name,
            isAdmin: clients[username].isAdmin
        }));
        
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error al obtener usuarios' });
    }
});

app.post('/api/users', 
    requireAuth, 
    requireAdmin,
    [
        body('username')
            .isLength({ min: 1, max: 50 })
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('Usuario debe contener solo letras, números, guiones y guiones bajos'),
        body('password')
            .isLength({ min: 6, max: 100 })
            .withMessage('Contraseña debe tener al menos 6 caracteres'),
        body('name')
            .isLength({ min: 1, max: 100 })
            .withMessage('Nombre es requerido'),
        body('isAdmin')
            .isBoolean()
            .withMessage('Tipo de usuario inválido')
    ],
    handleValidationErrors,
    (req, res) => {
        try {
            const { username, password, name, isAdmin } = req.body;
            
            // Verificar si el usuario ya existe
            if (clients[username]) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'El usuario ya existe' 
                });
            }
            
            // Crear nuevo usuario
            clients[username] = {
                password: bcrypt.hashSync(password, 10),
                isAdmin: Boolean(isAdmin),
                name: name.trim()
            };
            
            // Crear directorio para el cliente si no es admin
            if (!isAdmin) {
                const clientDir = path.join(__dirname, 'uploads', username);
                fs.ensureDirSync(clientDir);
            }
            
            res.json({ 
                success: true, 
                message: 'Usuario creado exitosamente',
                user: {
                    username,
                    name: name.trim(),
                    isAdmin: Boolean(isAdmin)
                }
            });
            
        } catch (error) {
            console.error('Error creando usuario:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error interno del servidor' 
            });
        }
    }
);

app.delete('/api/users/:username', 
    requireAuth, 
    requireAdmin,
    [
        param('username')
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('Nombre de usuario inválido')
    ],
    handleValidationErrors,
    (req, res) => {
        try {
            const { username } = req.params;
            
            // No permitir eliminar el admin principal
            if (username === 'admin') {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No se puede eliminar el administrador principal' 
                });
            }
            
            // Verificar si el usuario existe
            if (!clients[username]) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Usuario no encontrado' 
                });
            }
            
            // No permitir que un usuario se elimine a sí mismo
            if (username === req.session.user.username) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No puedes eliminarte a ti mismo' 
                });
            }
            
            // Eliminar usuario
            delete clients[username];
            
            res.json({ 
                success: true, 
                message: 'Usuario eliminado exitosamente' 
            });
            
        } catch (error) {
            console.error('Error eliminando usuario:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error interno del servidor' 
            });
        }
    }
);

app.get('/api/files/:clientId', requireAuth, (req, res) => {
    const clientId = req.params.clientId;
    
    // Verificar permisos
    if (!req.session.user.isAdmin && req.session.user.username !== clientId) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    
    const clientPath = path.join(__dirname, 'uploads', clientId);
    
    if (!fs.existsSync(clientPath)) {
        return res.json({ files: {} });
    }
    
    const fileStructure = {};
    
    try {
        const years = fs.readdirSync(clientPath);
        
        years.forEach(year => {
            const yearPath = path.join(clientPath, year);
            if (fs.statSync(yearPath).isDirectory()) {
                fileStructure[year] = {};
                
                const months = fs.readdirSync(yearPath);
                months.forEach(month => {
                    const monthPath = path.join(yearPath, month);
                    if (fs.statSync(monthPath).isDirectory()) {
                        const files = fs.readdirSync(monthPath)
                            .filter(file => file.endsWith('.pdf'))
                            .map(file => ({
                                name: file,
                                originalName: file.split('-').slice(1).join('-'),
                                uploadDate: fs.statSync(path.join(monthPath, file)).mtime
                            }));
                        fileStructure[year][month] = files;
                    }
                });
            }
        });
        
        res.json({ files: fileStructure });
    } catch (error) {
        res.json({ files: {} });
    }
});

app.get('/download/:clientId/:year/:month/:filename', 
    requireAuth,
    [
        param('clientId')
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('ID de cliente inválido'),
        param('year')
            .matches(/^\d{4}$/)
            .withMessage('Año inválido'),
        param('month')
            .matches(/^[a-zA-Z]+$/)
            .withMessage('Mes inválido'),
        param('filename')
            .matches(/^[a-zA-Z0-9._ -]+$/)
            .isLength({ max: 255 })
            .withMessage('Nombre de archivo inválido')
    ],
    handleValidationErrors,
    (req, res) => {
        const { clientId, year, month, filename } = req.params;
        
        // Verificar permisos
        if (!req.session.user.isAdmin && req.session.user.username !== clientId) {
            return res.status(403).json({ error: 'Acceso denegado' });
        }
        
        // Construir ruta y validar contra path traversal
        const relativePath = path.join(clientId, year, month, filename);
        const basePath = path.join(__dirname, 'uploads');
        
        if (!validatePath(relativePath, basePath)) {
            return res.status(400).json({ error: 'Ruta de archivo inválida' });
        }
        
        const filePath = path.join(basePath, relativePath);
        
        // Verificar que el archivo existe y está dentro del directorio permitido
        if (fs.existsSync(filePath) && filePath.startsWith(basePath)) {
            // Configurar headers de seguridad para descarga
            res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filename)}"`);
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.download(filePath);
        } else {
            res.status(404).json({ error: 'Archivo no encontrado' });
        }
    }
);

// Ruta para eliminar archivos (solo admin)
app.delete('/api/files/:clientId/:year/:month/:filename', 
    requireAuth,
    requireAdmin,
    [
        param('clientId')
            .matches(/^[a-zA-Z0-9_-]+$/)
            .withMessage('ID de cliente inválido'),
        param('year')
            .matches(/^\d{4}$/)
            .withMessage('Año inválido'),
        param('month')
            .matches(/^[a-zA-Z]+$/)
            .withMessage('Mes inválido'),
        param('filename')
            .matches(/^[a-zA-Z0-9._ -]+$/)
            .isLength({ max: 255 })
            .withMessage('Nombre de archivo inválido')
    ],
    handleValidationErrors,
    (req, res) => {
        try {
            const { clientId, year, month, filename } = req.params;
            
            // Construir ruta y validar contra path traversal
            const relativePath = path.join(clientId, year, month, filename);
            const basePath = path.join(__dirname, 'uploads');
            
            if (!validatePath(relativePath, basePath)) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Ruta de archivo inválida' 
                });
            }
            
            const filePath = path.join(basePath, relativePath);
            
            // Verificar que el archivo existe y está dentro del directorio permitido
            if (!fs.existsSync(filePath) || !filePath.startsWith(basePath)) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Archivo no encontrado' 
                });
            }
            
            // Eliminar el archivo
            fs.unlinkSync(filePath);
            
            res.json({ 
                success: true, 
                message: 'Archivo eliminado exitosamente' 
            });
            
        } catch (error) {
            console.error('Error eliminando archivo:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error interno del servidor' 
            });
        }
    }
);

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
try {
    fs.ensureDirSync(uploadsDir);
    console.log('Directorio uploads verificado/creado');
} catch (error) {
    console.error('Error al crear directorio uploads:', error);
}

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    console.log('Credenciales de prueba:');
    console.log('Admin: admin / admin123');
    console.log('Cliente 1: cliente1 / pass123');
    console.log('Cliente 2: cliente2 / pass456');
});

module.exports = app;