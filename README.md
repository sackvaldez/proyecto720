# Sistema de Gestión de Archivos - Caballero Solutions Power

Sistema web para la gestión y distribución de documentos (pólizas, análisis de aceites y termografías) entre la empresa Caballero Solutions Power y sus clientes.

## Características

- **Subida de archivos**: Los administradores pueden subir archivos PDF organizados por cliente, año y mes
- **Acceso controlado**: Cada cliente tiene credenciales específicas para acceder solo a sus documentos
- **Organización temporal**: Los archivos se organizan por años (2024, 2025, 2026) y meses
- **Soporte de archivos grandes**: Hasta 100MB por archivo
- **Interfaz funcional**: Diseño simple y eficiente, priorizando funcionalidad

## Características Técnicas

- **Autenticación segura** con bcrypt para hash de contraseñas
- **Gestión de sesiones** con express-session y configuración segura
- **Validación de archivos** (solo PDFs, máximo 100MB)
- **Estructura de carpetas** organizada por cliente/año/mes
- **Interfaz responsive** adaptable a diferentes dispositivos

## 🔒 Seguridad Implementada

- **Headers de seguridad** con Helmet.js (CSP, XSS protection, etc.)
- **Rate limiting** para prevenir ataques de fuerza bruta
- **Validación de entrada** con express-validator
- **Protección contra path traversal** en rutas de archivos
- **Sanitización de nombres de archivo**
- **Sesiones seguras** con HttpOnly, SameSite y Secure flags
- **Validación estricta de tipos MIME** y extensiones de archivo

Para más detalles, consulta [SECURITY.md](./SECURITY.md)

## Tecnologías Utilizadas

- **Backend**: Node.js con Express
- **Subida de archivos**: Multer
- **Autenticación**: bcryptjs + express-session
- **Frontend**: HTML, CSS, JavaScript vanilla
- **Almacenamiento**: Sistema de archivos local

## Instalación y Uso

### Prerrequisitos
- Node.js (versión 14 o superior)
- npm

### Instalación

1. Instalar dependencias:
```bash
npm install
```

2. Iniciar el servidor:
```bash
npm start
```

3. Acceder al sistema:
```
http://localhost:3000
```

## Credenciales de Prueba

### Administrador
- **Usuario**: admin
- **Contraseña**: admin123
- **Permisos**: Subir archivos, ver todos los clientes

### Clientes de Ejemplo
- **Cliente 1**:
  - Usuario: cliente1
  - Contraseña: pass123
  
- **Cliente 2**:
  - Usuario: cliente2
  - Contraseña: pass456

## Estructura del Sistema

### Panel de Administración
- Subida de archivos por cliente, año y mes
- Visualización de todos los clientes registrados
- Gestión de documentos

### Portal del Cliente
- Visualización de documentos organizados por año y mes
- Descarga de archivos PDF
- Interfaz intuitiva con navegación por años expandibles

## Estructura de Archivos

```
proyecto720/
├── server.js              # Servidor principal
├── package.json           # Dependencias del proyecto
├── public/                # Archivos estáticos
│   ├── login.html        # Página de login
│   ├── admin.html        # Panel de administración
│   └── client.html       # Portal del cliente
├── uploads/              # Archivos subidos (se crea automáticamente)
│   └── [clientId]/
│       └── [year]/
│           └── [month]/
│               └── archivos.pdf
└── README.md             # Este archivo
```

## Funcionalidades Principales

### Para Administradores
1. **Subir archivos**: Seleccionar cliente, año, mes y archivo PDF
2. **Gestión de clientes**: Ver lista de clientes registrados
3. **Visualización de archivos**: Acceder a los archivos de cualquier cliente

### Para Clientes
1. **Acceso seguro**: Login con credenciales específicas
2. **Navegación por años**: Expandir/contraer años para ver documentos
3. **Descarga de archivos**: Descargar documentos PDF directamente
4. **Organización clara**: Documentos organizados por mes dentro de cada año

## Seguridad

- Autenticación basada en sesiones
- Contraseñas encriptadas con bcrypt
- Verificación de permisos en cada solicitud
- Validación de tipos de archivo (solo PDF)
- Límite de tamaño de archivo (100MB)

## Personalización

### Agregar Nuevos Clientes
Editar el objeto `clients` en `server.js`:

```javascript
const clients = {
    'nuevo_cliente': {
        password: bcrypt.hashSync('contraseña_segura', 10),
        isAdmin: false,
        name: 'Nombre del Cliente'
    }
};
```

### Modificar Años Disponibles
Editar las opciones en `admin.html`:

```html
<select id="year" name="year" required>
    <option value="2024">2024</option>
    <option value="2025">2025</option>
    <option value="2026">2026</option>
    <!-- Agregar más años según necesidad -->
</select>
```

## 🚀 Pasos para Producción

### 1. Configuración de Entorno
```bash
# Copiar variables de entorno
cp .env.example .env

# Editar variables críticas
NODE_ENV=production
SESSION_SECRET=tu-clave-super-secreta-aqui
```

### 2. Base de Datos
- Migrar de memoria a PostgreSQL/MySQL
- Configurar conexiones SSL
- Implementar backups automáticos

### 3. HTTPS/SSL
- Obtener certificados SSL (Let's Encrypt recomendado)
- Configurar servidor web (Nginx/Apache)
- Habilitar HTTP/2

### 4. Servidor
- Usar PM2 para gestión de procesos
- Configurar reverse proxy
- Implementar monitoreo y logs

### 5. Seguridad Adicional
- Configurar firewall
- Implementar 2FA (opcional)
- Auditoría regular de dependencias

Para guía detallada, consulta [SECURITY.md](./SECURITY.md)

## Notas Importantes

- Los archivos se almacenan en el sistema de archivos local (considerar almacenamiento en la nube para producción)
- Para producción, **se DEBE migrar a una base de datos real** (PostgreSQL/MySQL)
- El sistema está optimizado para funcionalidad sobre estética
- Soporta archivos PDF de hasta 100MB
- La organización por años y meses facilita la navegación
- Las credenciales están hardcodeadas para propósitos de demostración. **Cambiar en producción**

## Soporte

Para soporte técnico o consultas sobre el sistema, contactar al equipo de desarrollo de Caballero Solutions Power.