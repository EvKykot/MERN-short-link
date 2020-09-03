const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

/**
 * /api/auth/register
 */
router.post(
  '/register',
  [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'To short password').isLength({min: 6}),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect registration data',
        });
      }

      const {email, password} = req.body;
      const candidate = await User.findOne({email});

      if (candidate) {
        return res.status(400).json({message: 'user with same email already exist'});
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({email, password: hashedPassword});

      await user.save();

      res.status(201).json({message: 'User is created'});
    } catch (e) {
      res.status(500).json({ message: 'something went wrong'});
    }
  }
);

/**
 * /api/auth/login
 */
router.post(
  '/login',
  [
    // check('email', 'Incorrect email').normalizeEmail().isEmail(),
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Incorrect password').exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect login data',
        });
      }

      const {email, password} = req.body;
      const user = await User.findOne({email});

      if (!user) {
        return res.status(400).json({message: 'User with this email is not exist'})
      }

      const isPasswordMatch = await bcrypt.compare(password, user.password);

      if (!isPasswordMatch) {
        return res.status(400).json({message: 'Password is incorrect'});
      }

      const token = jwt.sign(
        {userId: user.id},
        config.get('jwtSecret'),
        {expiresIn: '1h'},
      );

      return res.json({token, userId: user.id});
    } catch (e) {
      res.status(500).json({ message: 'something went wrong'});
    }
  }
);

/**
 *
 */
module.exports = router;
