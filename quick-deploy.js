#!/usr/bin/env node

/**
 * Script de deploy rápido para Render
 * Hace commit y push de los cambios
 */

const { execSync } = require('child_process');
const fs = require('fs');

console.log('🚀 Iniciando deploy rápido...');

try {
    // Verificar si hay cambios
    console.log('📋 Verificando cambios...');
    const status = execSync('git status --porcelain', { encoding: 'utf8' });
    
    if (!status.trim()) {
        console.log('ℹ️  No hay cambios para deployar');
        process.exit(0);
    }
    
    console.log('📝 Cambios detectados:');
    console.log(status);
    
    // Agregar todos los archivos
    console.log('➕ Agregando archivos...');
    execSync('git add .', { stdio: 'inherit' });
    
    // Hacer commit
    const commitMessage = process.argv[2] || 'Fix: Configurar trust proxy para Render';
    console.log(`💾 Haciendo commit: "${commitMessage}"`);
    execSync(`git commit -m "${commitMessage}"`, { stdio: 'inherit' });
    
    // Push a GitHub
    console.log('🌐 Subiendo a GitHub...');
    execSync('git push origin main', { stdio: 'inherit' });
    
    console.log('\n✅ Deploy iniciado exitosamente!');
    console.log('\n📊 Próximos pasos:');
    console.log('1. Ir a Render Dashboard');
    console.log('2. Monitorear logs del deploy');
    console.log('3. Verificar que el login funcione');
    console.log('\n🔗 URLs útiles:');
    console.log('- Dashboard: https://dashboard.render.com');
    console.log('- Tu app: https://tu-app.onrender.com');
    
} catch (error) {
    console.error('❌ Error durante el deploy:', error.message);
    process.exit(1);
}