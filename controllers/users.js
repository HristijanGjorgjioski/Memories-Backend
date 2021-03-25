import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from '../models/user.js';

export const signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const exsistingUser = await User.findOne({ email });

    if (!exsistingUser) return res.status(404).json({ message: 'User does not exsist.' });

    const isPasswordCorrect = await bcrypt.compare(password, exsistingUser.password);

    if (!isPasswordCorrect) return res.status(400).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ email: exsistingUser.email, id: exsistingUser._id }, 'test', { expiresIn: '1h' });

    res.status(200).json({ result: exsistingUser, token });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
};

export const signup = async (req, res) => {
  const { email, password, confirmPassword, firstName, lastName } = req.body;

  try {
    const exsistingUser = await User.findOne({ email });

    if (exsistingUser) return res.status(400).json({ message: 'User already exsist.' });

    if(password !== confirmPassword) return res.status(400).json({ message: 'Password do not match.' });

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await User.create({ email, password: hashedPassword, name: `${firstName} ${lastName}` });

    const token = jwt.sign({ email: result.email, id: result._id }, 'test', { expiresIn: '1h' });

    res.status(200).json({ result, token });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
};
