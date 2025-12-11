// app-completa-middleware.js
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const Joi = require("joi");

// Diccionario de Traducciones para mensajes de error
const i18nMessages = {
  es: {
    E400_INVALID_JSON: "JSON inválido en el body de la petición",
    E404_NOT_FOUND: "Ruta no encontrada",
    E401_AUTH_REQUIRED: "Token de autenticación requerido",
    E401_INVALID_TOKEN: "Token inválido",
    E401_INVALID_CREDENTIALS: "Credenciales inválidas",
    E403_INSUFFICIENT_PERMISSIONS: "Permisos insuficientes",
    E429_RATE_LIMIT: "Demasiadas peticiones (Rate Limit)",
    E500_INTERNAL: "Error interno del servidor",
    E400_MISSING_FIELDS: "Campos requeridos faltantes",

    M429_RATE_LIMIT_EXCEEDED: (limit, windowMs, timeLeft) =>
      `Has excedido el límite de ${limit} peticiones por ${
        windowMs / 1000
      } segundos. Intenta de nuevo en ${timeLeft} segundos.`,
  },
  en: {
    E400_INVALID_JSON: "Invalid JSON in the request body",
    E404_NOT_FOUND: "Route not found",
    E401_AUTH_REQUIRED: "Authentication token required",
    E401_INVALID_TOKEN: "Invalid token",
    E401_INVALID_CREDENTIALS: "Invalid credentials",
    E403_INSUFFICIENT_PERMISSIONS: "Insufficient permissions",
    E429_RATE_LIMIT: "Too Many Requests (Rate Limit)",
    E500_INTERNAL: "Internal Server Error",
    E400_MISSING_FIELDS: "Missing required fields",

    M429_RATE_LIMIT_EXCEEDED: (limit, windowMs, timeLeft) =>
      `You have exceeded the limit of ${limit} requests per ${
        windowMs / 1000
      } seconds. Try again in ${timeLeft} seconds.`,
  },
};

// Constantes de Rate Limit
const requestCounts = {};
const LIMIT_LOGIN = 5;
const WINDOW_LOGIN = 60 * 1000;
const LIMIT_API = 50;
const WINDOW_API = 60 * 1000;

// Constantes de Caché
const cache = {};
const CACHE_TTL = 30 * 1000;

// Idioma por defecto
const DEFAULT_LANGUAGE = "en";

// Crear aplicación
const app = express();

// Esquema para el login (POST /auth/login)
const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "El email debe ser una dirección de email válida.",
    "any.required": "El campo email es obligatorio.",
  }),
  password: Joi.string().min(6).required().messages({
    "string.min": "La contraseña debe tener al menos 6 caracteres.",
    "any.required": "El campo password es obligatorio.",
  }),
});

// Esquema para la creación de usuario (POST /api/usuarios)
const crearUsuarioSchema = Joi.object({
  nombre: Joi.string().min(3).max(100).required().messages({
    "string.min": "El nombre debe tener al menos 3 caracteres.",
    "string.max": "El nombre no debe exceder los 100 caracteres.",
    "any.required": "El campo nombre es obligatorio.",
  }),
  email: Joi.string().email().required().messages({
    "string.email": "El email debe ser una dirección de email válida.",
    "any.required": "El campo email es obligatorio.",
  }),
  activo: Joi.boolean().optional(),
});

// Middleware de terceros
app.use(helmet()); // Seguridad
app.use(cors()); // CORS
app.use(compression()); // Compresión
app.use(express.json({ limit: "10mb" })); // Parsear JSON
app.use(express.urlencoded({ extended: true })); // Parsear formularios
app.use(i18nMiddleware); // Internacionalización (i18n)

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

// Middleware personalizado: Rate Limiting personalizado
function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const key = `${req.url}-${req.ip}`;
    const now = Date.now();

    if (!requestCounts[key]) {
      requestCounts[key] = {
        count: 0,
        lastReset: now,
      };
    }

    const client = requestCounts[key];

    if (now - client.lastReset > windowMs) {
      client.count = 1;
      client.lastReset = now;
      return next();
    }

    if (client.count >= limit) {
      const timeLeft = Math.ceil((client.lastReset + windowMs - now) / 1000);

      res.set("X-RateLimit-Limit", limit);
      res.set("X-RateLimit-Remaining", 0);
      res.set("Retry-After", timeLeft);

      return res.status(429).json({
        error: res.locals.t("E429_RATE_LIMIT"),
        mensaje: res.locals.t(
          "M429_RATE_LIMIT_EXCEEDED",
          limit,
          windowMs,
          timeLeft
        ),
        timestamp: res.locals.timestamp,
      });
    }

    client.count++;

    res.set("X-RateLimit-Limit", limit);
    res.set("X-RateLimit-Remaining", limit - client.count);

    next();
  };
}

// Middleware personalizado: validar el body de la petición contra un esquema Joi.
function validarEsquema(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      allowUnknown: false,
    });

    if (error) {
      const errores = error.details.map((detail) => ({
        campo: detail.context.key,
        mensaje: detail.message.replace(/['"]/g, ""),
        tipo: detail.type,
      }));

      return res.status(400).json({
        error: "Error de validación de datos",
        detalles: errores,
        timestamp: res.locals.timestamp,
      });
    }

    req.body = value;
    next();
  };
}

// Middleware personalizado: Caché en memoria para peticiones GET
function cacheResponse(req, res, next) {
  if (req.method !== "GET") {
    return next();
  }

  const key = req.originalUrl || req.url;
  const now = Date.now();
  const cachedItem = cache[key];

  if (cachedItem && now - cachedItem.timestamp < CACHE_TTL) {
    console.log(`[${new Date().toISOString()}] Caché HIT: ${key}`);

    res.set("X-Cache-Status", "HIT");
    res.set("Cache-Control", `public, max-age=${CACHE_TTL / 1000}`);

    return res.json(cachedItem.data);
  }

  console.log(`[${new Date().toISOString()}] Caché MISS: ${key}`);
  res.set("X-Cache-Status", "MISS");

  const originalJson = res.json;

  res.json = function (body) {
    if (res.statusCode === 200) {
      cache[key] = {
        timestamp: Date.now(),
        data: body,
      };

      console.log(`[${new Date().toISOString()}] Caché SET: ${key}`);
      res.set("Cache-Control", `public, max-age=${CACHE_TTL / 1000}`);
    }

    originalJson.call(this, body);
  };

  next();
}

// Middleware personalizado: internacionalización (i18n)
function i18nMiddleware(req, res, next) {
  const supportedLangs = Object.keys(i18nMessages);

  let lang = req.acceptsLanguages(supportedLangs);

  if (!lang) {
    lang = DEFAULT_LANGUAGE;
  }

  const translations = i18nMessages[lang] || i18nMessages[DEFAULT_LANGUAGE];

  if (!translations) {
    console.error(
      `ERROR: Las traducciones para el idioma ${lang} o ${DEFAULT_LANGUAGE} no existen en i18nMessages.`
    );
  }

  res.locals.t = (key, ...args) => {
    const message = translations[key];
    if (typeof message === "function") {
      return message(...args);
    }
    return message || key;
  };

  res.locals.lang = lang;

  console.log(`[${new Date().toISOString()}] Idioma detectado: ${lang}`);

  next();
}

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
      error: res.locals.t("E401_AUTH_REQUIRED"),
      timestamp: res.locals.timestamp,
    });
  }

  const token = authHeader.substring(7); // Remover 'Bearer '

  // Simular validación de token (en producción usar JWT)
  if (token !== "mi-token-secreto") {
    return res.status(401).json({
      error: res.locals.t("E401_INVALID_TOKEN"),
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
        error: res.locals.t("E401_AUTH_REQUIRED"),
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
        error: res.locals.t("E403_INSUFFICIENT_PERMISSIONS"),
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
        error: res.locals.t("E400_MISSING_FIELDS"),
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
  rateLimit(LIMIT_LOGIN, WINDOW_LOGIN),
  validarEsquema(loginSchema),
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
        error: res.locals.t("E401_INVALID_CREDENTIALS"),
        timestamp: res.locals.timestamp,
      });
    }
  }
);

// Rutas protegidas - Usuarios
app.get(
  "/api/usuarios",
  rateLimit(LIMIT_API, WINDOW_API),
  validarAuth,
  cacheResponse,
  (req, res) => {
    res.json({
      usuarios,
      total: usuarios.length,
      timestamp: res.locals.timestamp,
    });
  }
);

app.post(
  "/api/usuarios",
  rateLimit(LIMIT_API, WINDOW_API),
  validarAuth,
  validarPermisos("escribir"),
  validarEsquema(crearUsuarioSchema),
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
app.get(
  "/api/productos",
  rateLimit(LIMIT_API, WINDOW_API),
  validarAuth,
  cacheResponse,
  (req, res) => {
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
  }
);

app.post(
  "/api/productos",
  rateLimit(LIMIT_API, WINDOW_API),
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
      error: res.locals.t("E400_INVALID_JSON"),
      timestamp: res.locals.timestamp,
    });
  }

  // Error genérico
  res.status(500).json({
    error: res.locals.t("E500_INTERNAL"),
    mensaje:
      process.env.NODE_ENV === "development" ? error.message : "Algo salió mal",
    timestamp: res.locals.timestamp,
  });
});

// Middleware 404
app.use((req, res) => {
  console.log(res.locals.t("E404_NOT_FOUND"));

  res.status(404).json({
    error: res.locals.t("E404_NOT_FOUND"),
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
