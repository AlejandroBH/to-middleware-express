// app-completa-middleware.js
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");

// Crear aplicación
const app = express();

// Middleware de terceros
app.use(helmet()); // Seguridad
app.use(cors()); // CORS
app.use(compression()); // Compresión
app.use(express.json({ limit: "10mb" })); // Parsear JSON
app.use(express.urlencoded({ extended: true })); // Parsear formularios

// Middleware personalizado: Logger detallado
app.use((req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();

  console.log(`[${timestamp}] ${req.method} ${req.url} - IP: ${req.ip}`);

  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.url} - ${
        res.statusCode
      } - ${duration}ms`
    );
  });

  next();
});

// Middleware personalizado: Agregar timestamp a todas las respuestas
app.use((req, res, next) => {
  res.locals.timestamp = new Date().toISOString();
  next();
});

// Base de datos simulada
let usuarios = [
  { id: 1, nombre: "Ana García", email: "ana@example.com", activo: true },
  { id: 2, nombre: "Carlos López", email: "carlos@example.com", activo: true },
  {
    id: 3,
    nombre: "María Rodríguez",
    email: "maria@example.com",
    activo: false,
  },
];

let productos = [
  { id: 1, nombre: "Laptop", precio: 1200, categoria: "Electrónica", stock: 5 },
  { id: 2, nombre: "Mouse", precio: 25, categoria: "Accesorios", stock: 20 },
  { id: 3, nombre: "Teclado", precio: 75, categoria: "Accesorios", stock: 15 },
];

// Middleware personalizado: Validación de autenticación (simple)
function validarAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Token de autenticación requerido",
      timestamp: res.locals.timestamp,
    });
  }

  const token = authHeader.substring(7); // Remover 'Bearer '

  // Simular validación de token (en producción usar JWT)
  if (token !== "mi-token-secreto") {
    return res.status(401).json({
      error: "Token inválido",
      timestamp: res.locals.timestamp,
    });
  }

  // Agregar info del usuario al request
  req.usuario = { id: 1, nombre: "Admin", role: "admin" };
  next();
}

// Middleware personalizado: Validación de permisos
function validarPermisos(permisoRequerido) {
  return (req, res, next) => {
    if (!req.usuario) {
      return res.status(401).json({
        error: "Usuario no autenticado",
        timestamp: res.locals.timestamp,
      });
    }

    // Simular permisos (en producción consultar BD)
    const permisosUsuario = {
      1: ["leer", "escribir", "admin"], // Admin tiene todos
    };

    const permisos = permisosUsuario[req.usuario.id] || [];

    if (!permisos.includes(permisoRequerido)) {
      return res.status(403).json({
        error: "Permisos insuficientes",
        timestamp: res.locals.timestamp,
      });
    }

    next();
  };
}

// Middleware personalizado: Validación de datos
function validarCamposRequeridos(campos) {
  return (req, res, next) => {
    const faltantes = [];

    for (const campo of campos) {
      if (!req.body[campo]) {
        faltantes.push(campo);
      }
    }

    if (faltantes.length > 0) {
      return res.status(400).json({
        error: "Campos requeridos faltantes",
        camposFaltantes: faltantes,
        timestamp: res.locals.timestamp,
      });
    }

    next();
  };
}

// Rutas públicas
app.get("/", (req, res) => {
  res.json({
    mensaje: "API REST con Express.js - Middleware Completo",
    version: "1.0.0",
    timestamp: res.locals.timestamp,
    rutasPublicas: ["GET /", "GET /health", "POST /auth/login"],
    rutasProtegidas: [
      "GET /api/usuarios",
      "POST /api/usuarios",
      "GET /api/productos",
      "POST /api/productos",
    ],
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: res.locals.timestamp,
  });
});

// Simulación de login (retorna token fijo)
app.post(
  "/auth/login",
  validarCamposRequeridos(["email", "password"]),
  (req, res) => {
    const { email, password } = req.body;

    // Simular validación (en producción consultar BD)
    if (email === "admin@example.com" && password === "admin123") {
      res.json({
        token: "mi-token-secreto",
        usuario: { id: 1, nombre: "Admin", role: "admin" },
        timestamp: res.locals.timestamp,
      });
    } else {
      res.status(401).json({
        error: "Credenciales inválidas",
        timestamp: res.locals.timestamp,
      });
    }
  }
);

// Rutas protegidas - Usuarios
app.get("/api/usuarios", validarAuth, (req, res) => {
  res.json({
    usuarios,
    total: usuarios.length,
    timestamp: res.locals.timestamp,
  });
});

app.post(
  "/api/usuarios",
  validarAuth,
  validarPermisos("escribir"),
  validarCamposRequeridos(["nombre", "email"]),
  (req, res) => {
    const nuevoUsuario = {
      id: usuarios.length + 1,
      nombre: req.body.nombre,
      email: req.body.email,
      activo: req.body.activo !== undefined ? req.body.activo : true,
      fechaCreacion: res.locals.timestamp,
    };

    usuarios.push(nuevoUsuario);

    res.status(201).json({
      mensaje: "Usuario creado exitosamente",
      usuario: nuevoUsuario,
      timestamp: res.locals.timestamp,
    });
  }
);

// Rutas protegidas - Productos
app.get("/api/productos", validarAuth, (req, res) => {
  const { categoria, precio_min, precio_max } = req.query;
  let resultados = [...productos];

  // Filtros
  if (categoria) {
    resultados = resultados.filter((p) => p.categoria === categoria);
  }

  if (precio_min) {
    resultados = resultados.filter((p) => p.precio >= parseFloat(precio_min));
  }

  if (precio_max) {
    resultados = resultados.filter((p) => p.precio <= parseFloat(precio_max));
  }

  res.json({
    productos: resultados,
    total: resultados.length,
    filtros: req.query,
    timestamp: res.locals.timestamp,
  });
});

app.post(
  "/api/productos",
  validarAuth,
  validarPermisos("escribir"),
  validarCamposRequeridos(["nombre", "precio", "categoria"]),
  (req, res) => {
    const nuevoProducto = {
      id: productos.length + 1,
      nombre: req.body.nombre,
      precio: parseFloat(req.body.precio),
      categoria: req.body.categoria,
      stock: req.body.stock || 0,
      fechaCreacion: res.locals.timestamp,
    };

    productos.push(nuevoProducto);

    res.status(201).json({
      mensaje: "Producto creado exitosamente",
      producto: nuevoProducto,
      timestamp: res.locals.timestamp,
    });
  }
);

// Middleware de manejo de errores (debe ser el último)
app.use((error, req, res, next) => {
  console.error("Error:", error);

  // Errores de JSON inválido
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "JSON inválido en el body de la petición",
      timestamp: res.locals.timestamp,
    });
  }

  // Error genérico
  res.status(500).json({
    error: "Error interno del servidor",
    mensaje:
      process.env.NODE_ENV === "development" ? error.message : "Algo salió mal",
    timestamp: res.locals.timestamp,
  });
});

// Middleware 404
app.use((req, res) => {
  res.status(404).json({
    error: "Ruta no encontrada",
    metodo: req.method,
    ruta: req.url,
    timestamp: res.locals.timestamp,
    sugerencias: [
      "GET / - Información general",
      "GET /health - Estado del servidor",
      "POST /auth/login - Autenticación",
      "GET /api/usuarios - Listar usuarios (requiere auth)",
      "GET /api/productos - Listar productos (requiere auth)",
    ],
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `🚀 API Express con Middleware Completo en http://localhost:${PORT}`
  );
  console.log(`📖 Documentación en http://localhost:${PORT}`);
  console.log(
    `🔐 Autenticación: POST /auth/login con {"email":"admin@example.com","password":"admin123"}`
  );
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n👋 Cerrando servidor...");
  process.exit(0);
});
