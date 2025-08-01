# 🚀 Guía de Deploy en Render

## Pasos para deployar en Render

### 1. Preparar el repositorio

✅ **Ya completado:**
- `.gitignore` creado
- `package.json` actualizado con engines de Node.js
- `render.yaml` configurado
- Variables de entorno preparadas

### 2. Subir código a GitHub

```bash
git add .
git commit -m "Preparar aplicación para deploy en Render"
git push origin main
```

### 3. Configurar en Render

1. **Ir a [render.com](https://render.com)**
2. **Hacer clic en "New +"**
3. **Seleccionar "Web Service"**
4. **Conectar tu repositorio de GitHub**
5. **Configurar el servicio:**

   - **Name:** `caballero-solutions-power`
   - **Environment:** `Node`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Plan:** `Free` (para empezar)

### 4. Variables de entorno en Render

En la sección "Environment Variables" agregar:

```
NODE_ENV=production
SESSION_SECRET=[Render generará automáticamente]
```

### 5. Configuración de disco persistente

1. **En "Settings" > "Disks"**
2. **Agregar nuevo disco:**
   - **Name:** `uploads`
   - **Mount Path:** `/opt/render/project/src/uploads`
   - **Size:** `1 GB` (plan gratuito)

### 6. Deploy automático

- Render detectará automáticamente los cambios en GitHub
- El deploy se ejecutará automáticamente
- La aplicación estará disponible en: `https://tu-app.onrender.com`

## 🔧 Configuración actual

### Características implementadas:
- ✅ Almacenamiento en memoria (temporal)
- ✅ Subida de archivos hasta 200MB
- ✅ Gestión de usuarios
- ✅ Autenticación y autorización
- ✅ Interfaz responsive
- ✅ Eliminación de archivos (admin)

### Limitaciones actuales:
- ⚠️ Datos de usuarios se pierden al reiniciar
- ⚠️ Archivos se almacenan en disco local
- ⚠️ No hay backup automático

## 🔄 Próximos pasos (después del deploy inicial)

### 1. Migrar a PostgreSQL
- Agregar PostgreSQL database en Render
- Migrar datos de usuarios
- Implementar persistencia

### 2. Migrar almacenamiento de archivos
- Configurar AWS S3 o Cloudinary
- Migrar archivos existentes
- Actualizar rutas de descarga

### 3. Mejoras de producción
- Implementar logs estructurados
- Agregar monitoreo
- Configurar backups automáticos

## 📞 Credenciales de prueba

```
Admin: admin / admin123
Cliente 1: cliente1 / pass123
Cliente 2: cliente2 / pass456
```

## 🆘 Troubleshooting

### Error de build
- Verificar que `package.json` tenga engines de Node.js
- Revisar que todas las dependencias estén en `dependencies`

### Error de start
- Verificar que el comando start sea `npm start`
- Revisar logs en Render dashboard

### Archivos no se suben
- Verificar que el disco persistente esté configurado
- Revisar permisos de escritura

### Sesiones no persisten
- Verificar que `SESSION_SECRET` esté configurado
- Revisar configuración de cookies en producción