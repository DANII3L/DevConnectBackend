const express = require('express');
const ProfileController = require('../controllers/profileController');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// ⚠️ IMPORTANTE: /me DEBE IR ANTES DE /:id
router.get('/me', authenticateToken, ProfileController.getMyProfile);
router.put('/update', authenticateToken, ProfileController.updateProfile);

// Rutas públicas
router.get('/', ProfileController.getAllProfiles);
router.get('/search/:query', ProfileController.searchProfiles);
router.get('/stats', ProfileController.getProfileStats);
router.get('/:id', ProfileController.getProfileById);

module.exports = router;