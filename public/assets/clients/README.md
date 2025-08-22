# Imágenes Personalizadas de Clientes

Este directorio contiene las imágenes de fondo personalizadas para cada cliente.

## 📁 Estructura de Archivos

Cada cliente debe tener su imagen con el nombre correspondiente a su username:

```
clients/
├── plasman.jpg (o .svg, .png)
├── plasman2.svg ✅ (ejemplo incluido)
├── rehrig.jpg
├── martin.jpg
├── fareva.jpg
├── givaudan.jpg
├── philips.jpg
├── indorama.jpg
├── stant.jpg
└── martin2.jpg
```

## 🎨 Formatos Recomendados

### Formatos Soportados:
- **SVG** (Recomendado): Escalable, ligero, ideal para logos
- **JPG**: Para fotografías, buena compresión
- **PNG**: Para imágenes con transparencia

### Dimensiones Recomendadas:
- **Mínimo**: 1920x1080px (Full HD)
- **Óptimo**: 2560x1440px (2K)
- **Máximo**: 3840x2160px (4K)

## 🔧 Cómo Agregar una Nueva Imagen

1. **Preparar la imagen**:
   - Asegúrate de que tenga buena resolución
   - Optimiza el tamaño del archivo (máx. 2MB recomendado)
   - Usa colores que contrasten bien con texto blanco

2. **Nombrar el archivo**:
   - Usa el username exacto del cliente
   - Ejemplo: `plasman2.jpg` para el usuario `plasman2`

3. **Subir el archivo**:
   - Coloca la imagen en este directorio
   - El sistema la detectará automáticamente

4. **Actualizar CSS (si es necesario)**:
   - El CSS ya está configurado para `.jpg`
   - Si usas otro formato, actualiza en `client-themes.css`

## 🎯 Ejemplo de Personalización

```css
/* En client-themes.css */
.theme-plasman2 {
    background: linear-gradient(135deg, rgba(45, 85, 135, 0.9), rgba(45, 85, 135, 0.7)), 
                url('/assets/clients/plasman2.svg') center/cover;
}
```

## 📝 Lista de Clientes

| Username | Nombre Completo | Estado Imagen |
|----------|-----------------|---------------|
| plasman | PLASMAN | ⏳ Pendiente |
| plasman2 | PLASMAN PLANTA 2 | ✅ Completado |
| rehrig | REHRIG | ⏳ Pendiente |
| martin | MARTIN | ⏳ Pendiente |
| fareva | FAREVA | ⏳ Pendiente |
| givaudan | GIVAUDAN | ⏳ Pendiente |
| philips | PHILIPS | ⏳ Pendiente |
| indorama | INDORAMA | ⏳ Pendiente |
| stant | STANT DE MEXICO | ⏳ Pendiente |
| martin2 | MARTIN 2 | ⏳ Pendiente |

## 🚀 Pruebas Locales

Para probar las imágenes localmente:

1. Inicia el servidor: `npm start`
2. Inicia sesión con las credenciales del cliente
3. Verifica que la imagen de fondo se muestre correctamente
4. Prueba en diferentes dispositivos/resoluciones

## 💡 Consejos de Diseño

- **Contraste**: Asegúrate de que el texto sea legible sobre la imagen
- **Branding**: Usa colores corporativos del cliente
- **Simplicidad**: Evita imágenes muy complejas que distraigan
- **Optimización**: Comprime las imágenes para mejorar la velocidad de carga

## 🔄 Fallback

Si no hay imagen personalizada, se usará el tema por defecto con el color corporativo asignado.