// routes/auth.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/get-question', authController.getSecretQuestion);
router.post('/verify-answer', authController.verifySecretAnswer);

module.exports = router;
