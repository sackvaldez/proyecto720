#!/usr/bin/env node

/**
 * Script de verificación pre-deploy
 * Verifica que la aplicación esté lista para producción
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Verificando configuración para deploy...');

let errors = [];
let warnings = [];

// Verificar archivos esenciales
const requiredFiles = [
    'package.json',
    'server.js',
    '.gitignore',
    'render.yaml',
    '.env.example'
];

requiredFiles.forEach(file => {
    if (!fs.existsSync(file)) {
        errors.push(`❌ Archivo faltante: ${file}`);
    } else {
        console.log(`✅ ${file} encontrado`);
    }
});

// Verificar package.json
try {
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    
    if (!pkg.engines || !pkg.engines.node) {
        warnings.push('⚠️  No se especifica versión de Node.js en engines');
    } else {
        console.log(`✅ Node.js version: ${pkg.engines.node}`);
    }
    
    if (!pkg.scripts || !pkg.scripts.start) {
        errors.push('❌ Script "start" faltante en package.json');
    } else {
        console.log(`✅ Start script: ${pkg.scripts.start}`);
    }
    
    // Verificar dependencias críticas
    const criticalDeps = ['express', 'multer', 'bcryptjs', 'express-session'];
    criticalDeps.forEach(dep => {
        if (!pkg.dependencies || !pkg.dependencies[dep]) {
            errors.push(`❌ Dependencia crítica faltante: ${dep}`);
        }
    });
    
} catch (error) {
    errors.push('❌ Error al leer package.json');
}

// Verificar .gitignore
try {
    const gitignore = fs.readFileSync('.gitignore', 'utf8');
    
    const requiredIgnores = ['node_modules/', 'uploads/', '.env'];
    requiredIgnores.forEach(ignore => {
        if (!gitignore.includes(ignore)) {
            warnings.push(`⚠️  .gitignore no incluye: ${ignore}`);
        }
    });
    
    console.log('✅ .gitignore verificado');
} catch (error) {
    errors.push('❌ Error al leer .gitignore');
}

// Verificar estructura de directorios
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    errors.push('❌ Directorio public/ faltante');
} else {
    const requiredPublicFiles = ['login.html', 'admin.html', 'client.html'];
    requiredPublicFiles.forEach(file => {
        if (!fs.existsSync(path.join(publicDir, file))) {
            errors.push(`❌ Archivo faltante: public/${file}`);
        }
    });
    console.log('✅ Directorio public verificado');
}

// Verificar server.js
try {
    const serverContent = fs.readFileSync('server.js', 'utf8');
    
    if (!serverContent.includes('process.env.PORT')) {
        warnings.push('⚠️  server.js no usa process.env.PORT');
    }
    
    if (!serverContent.includes('process.env.NODE_ENV')) {
        warnings.push('⚠️  server.js no verifica NODE_ENV');
    }
    
    console.log('✅ server.js verificado');
} catch (error) {
    errors.push('❌ Error al leer server.js');
}

// Mostrar resultados
console.log('\n📊 Resumen de verificación:');

if (errors.length === 0) {
    console.log('🎉 ¡Todo listo para deploy!');
} else {
    console.log('\n🚨 Errores que deben corregirse:');
    errors.forEach(error => console.log(error));
}

if (warnings.length > 0) {
    console.log('\n⚠️  Advertencias (recomendado corregir):');
    warnings.forEach(warning => console.log(warning));
}

console.log('\n📋 Próximos pasos:');
console.log('1. Corregir errores si los hay');
console.log('2. Subir código a GitHub: git add . && git commit -m "Deploy ready" && git push');
console.log('3. Crear Web Service en Render');
console.log('4. Configurar variables de entorno');
console.log('5. Configurar disco persistente para uploads');

process.exit(errors.length > 0 ? 1 : 0);