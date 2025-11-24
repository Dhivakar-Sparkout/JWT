const express = require('express');
const {
  registerUser,
  loginUser,
  refreshToken,
  logoutUser,
  dashboard
} = require('../controllers/authController');
const { authenticateToken } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/refresh-token', refreshToken);
router.post('/logout', logoutUser);
router.get('/dashboard', authenticateToken, dashboard);

module.exports = router;