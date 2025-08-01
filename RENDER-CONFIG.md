# 🎯 Configuración específica para Render

## 📋 Checklist de configuración

### 1. Configuración del Web Service

```yaml
Name: caballero-solutions-power
Environment: Node
Region: Oregon (US West) - Recomendado para mejor latencia
Branch: main
Root Directory: (dejar vacío)
Build Command: npm install
Start Command: npm start
```

### 2. Variables de entorno obligatorias

```bash
# En Render Dashboard > Environment Variables
NODE_ENV=production
SESSION_SECRET=[Generar automáticamente en Render]
```

**⚠️ IMPORTANTE:** 
- Usar "Generate" para SESSION_SECRET (más seguro)
- No usar valores por defecto en producción

### 3. Configuración de disco persistente

```yaml
Disk Name: uploads
Mount Path: /opt/render/project/src/uploads
Size: 1 GB (máximo en plan gratuito)
```

### 4. Configuración avanzada (opcional)

```yaml
Health Check Path: /
Auto-Deploy: Yes
Pull Request Previews: No (para ahorrar recursos)
```

## 🔧 Configuraciones específicas de Render

### Headers de seguridad
Render automáticamente agrega:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`

### HTTPS
- Render proporciona HTTPS automáticamente
- Certificados SSL/TLS renovados automáticamente

### Límites del plan gratuito
- 750 horas/mes de compute
- 1 GB de almacenamiento persistente
- 100 GB de ancho de banda
- Aplicación se suspende después de 15 min de inactividad

## 🚀 Proceso de deploy

1. **Push a GitHub:**
   ```bash
   git add .
   git commit -m "Preparar para deploy en Render"
   git push origin main
   ```

2. **Crear servicio en Render:**
   - Ir a https://dashboard.render.com
   - New > Web Service
   - Conectar repositorio
   - Usar configuración de arriba

3. **Configurar variables:**
   - Environment Variables
   - Agregar NODE_ENV y SESSION_SECRET

4. **Configurar disco:**
   - Settings > Disks
   - Add Disk con configuración de arriba

5. **Deploy:**
   - Render iniciará automáticamente
   - Monitorear logs en tiempo real

## 📊 Monitoreo post-deploy

### Verificar funcionamiento:
1. **Acceso a la aplicación:** `https://tu-app.onrender.com`
2. **Login admin:** admin / admin123
3. **Subir archivo de prueba**
4. **Verificar descarga**
5. **Probar con usuario cliente**

### Logs importantes:
```bash
# En Render logs buscar:
✅ "Servidor iniciado en puerto"
✅ "Directorio uploads verificado/creado"
✅ "Credenciales de prueba creadas"

❌ Errores de permisos en /uploads
❌ Errores de SESSION_SECRET
❌ Errores de dependencias
```

## 🔄 Actualizaciones futuras

### Deploy automático:
- Cada push a `main` triggerea nuevo deploy
- Render mantiene versiones anteriores
- Rollback disponible en caso de errores

### Escalabilidad:
- Upgrade a plan pagado para más recursos
- Múltiples instancias disponibles
- Load balancing automático

## 🆘 Troubleshooting común

### ❌ Error de login (X-Forwarded-For)
```bash
# Error en logs:
ValidationError: The 'X-Forwarded-For' header is set but the Express 'trust proxy' setting is false

# Solución aplicada:
- app.set('trust proxy', 1) en producción
- Validación xForwardedForHeader deshabilitada
- Deploy automático con fix incluido
```

### Build falla:
```bash
# Verificar en logs:
- npm install exitoso
- Todas las dependencias instaladas
- No errores de sintaxis
```

### Start falla:
```bash
# Verificar:
- Puerto correcto (process.env.PORT)
- Variables de entorno configuradas
- Directorio uploads creado
```

### Archivos no se guardan:
```bash
# Verificar:
- Disco persistente montado
- Permisos de escritura
- Ruta correcta (/opt/render/project/src/uploads)
```

### Sesiones no persisten:
```bash
# Verificar:
- SESSION_SECRET configurado
- Cookies habilitadas en navegador
- HTTPS funcionando
```

## 📞 URLs importantes

- **Dashboard:** https://dashboard.render.com
- **Docs:** https://render.com/docs
- **Status:** https://status.render.com
- **Support:** https://render.com/support