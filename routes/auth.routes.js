const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const saltRounds = 5;

const User = require('../models/User.model');

const router = require('express').Router();

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');

router.get('/signup', isLoggedOut, (req, res, next) => {
    res.render('auth/signup');
});


  
router.post('/signup', (req, res, next) => {
const { username, password } = req.body;

    if (!username || !password) {
        res.render('auth/signup', {
        errorMessage: 'All fields are required, please provide your username and password',
        });
        return;
    }

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res.status(500).render('auth/signup', {
        errorMessage:
            'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.',
        });
        return;
    }

    bcrypt
        .genSalt(saltRounds)
        .then((salt) => bcrypt.hash(password, salt))
        .then((hashedPassword) => {
        return User.create({ username, passwordHash: hashedPassword });
        })
        .then(() => {
        res.redirect('/profile');
        })
        .catch((err) => {
        if (err instanceof mongoose.Error.ValidationError) {
            res.status(500).render('auth/signup', { errorMessage: err.message });
        } else {
            next(err);
        }
        });
});

router.get('/profile', isLoggedIn, (req, res, next) => {
    res.render('profile', { user: req.session.currentUser });
  });
  
  router.get('/login', (req, res, next) => {
    res.render('auth/login');
  });
  
  router.post('/login', (req, res, next) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      res.render('auth/login', { errorMessage: 'Please provide both username and password' });
      return;
    }
  
    User.findOne({ username }).then((user) => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Username not found.' });
        return;
      } else if (bcrypt.compareSync(password, user.passwordHash)) {
        req.session.currentUser = user;
        console.log('req session', req.session);
        res.render('profile', { user });
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password' });
      }
    });
  });
  
  router.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
      if (err) next(err);
      res.redirect('/');
    });
  });

  
  
  module.exports = router;