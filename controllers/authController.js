// controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
  const { email, password, secretQuestion, secretAnswer } = req.body;

  try {
    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ message: 'Usuario ya existe' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedAnswer = await bcrypt.hash(secretAnswer, 10);

    const user = new User({ email, password: hashedPassword, secretQuestion, secretAnswer: hashedAnswer });
    await user.save();

    res.status(201).json({ message: 'Usuario registrado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar', error });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(401).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, { expiresIn: '7m' });


  res.status(200).json({ message: 'Login exitoso', token, refreshToken });
  } catch (error) {
  console.error("Error en login:", error.message);
  res.status(500).json({ message: 'Error en login', error: error.message });
}

};

exports.getSecretQuestion = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    res.status(200).json({ question: user.secretQuestion });
  } catch (error) {
    res.status(500).json({ message: 'Error', error });
  }
};

exports.verifySecretAnswer = async (req, res) => {
  const { email, secretAnswer, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    const isCorrect = await bcrypt.compare(secretAnswer, user.secretAnswer);
    if (!isCorrect) return res.status(401).json({ message: 'Respuesta incorrecta' });

    const hashedNewPass = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPass;
    await user.save();

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error', error });
  }
};

exports.refreshToken = (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ message: 'Refresh token requerido' });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      { expiresIn: '1m' }
    );

    res.status(200).json({ token: newAccessToken });
  } catch (error) {
    console.error("Error al verificar refresh:", error.message);
    res.status(403).json({ message: 'Refresh token inválido' });
  }
};
