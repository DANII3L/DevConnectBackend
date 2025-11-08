// BackDevConnect/src/routes/users.js
// Rutas de gestión de usuarios (solo admin)

const express = require('express');
const UserController = require('../controllers/userController');
const { authenticateToken, requireRole } = require('../middleware/auth');

const router = express.Router();

// Todas estas rutas requieren autenticación Y rol de admin
const requireAdmin = [authenticateToken, requireRole(['admin'])];

// Obtener todos los usuarios
router.get('/', requireAdmin, UserController.getAllUsers);

// Obtener usuario específico
router.get('/:id', requireAdmin, UserController.getUserById);

// Actualizar usuario (perfil completo incluyendo role)
router.put('/:id', requireAdmin, UserController.updateUser);

// Actualizar solo el rol de un usuario
router.put('/:id/role', requireAdmin, UserController.updateUserRole);

// Eliminar usuario
router.delete('/:id', requireAdmin, UserController.deleteUser);

module.exports = router;