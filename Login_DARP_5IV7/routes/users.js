var express = require('express');
var router = express.Router();
var db = require('../db');
var helpers = require('../helpers');
var errors = [];

router.get('/register', helpers.loginChecker, function (req, res, next) {

  res.render('register', {
    title: 'Registrate'
  });

});

router.post('/register', helpers.loginChecker, function (req, res, next) {

  if (!helpers.checkForm([req.body.email, req.body.psw, req.body.pswrepeat, req.body.fname])) {
    errors.push('Por favor llena todo el espacio!');
    next();
    return;
  }

  if (!helpers.validateEmail(req.body.email)) {
    errors.push('Por favor ingresa un correo valido!');
    next();
    return;
  }

  if (req.body.psw !== req.body.pswrepeat) {
    errors.push('Las contraseñas no coinciden');
    next();
    return;
  }

  var sqlQuery = `INSERT INTO users VALUES(NULL, ?, MD5(?), ?)`;
  var values = [req.body.email, req.body.psw, req.body.fname];

  db.query(sqlQuery, values, function (err, results, fields) {

    if (err) {
      errors.push(err.message);
      next();
      return;
    }

    if (results.affectedRows == 1) {
      res.redirect('/login');
      return;
    } else {
      errors.push(err.message);
      next();
    }

  });

});

router.post('/register', function (req, res, next) {

  res.statusCode = 401;

  res.render('register', {
    title: 'Registrate',
    messages: errors
  });

  errors = [];

});

router.get('/login', helpers.loginChecker, function (req, res, next) {

  res.render('login', {
    title: 'Login'
  });

});

router.post('/login', function (req, res, next) {

  if (!helpers.checkForm([req.body.email, req.body.psw])) {
    errors.push('Por favor llena todos los campos!');
    next();
    return;
  }

  if (!helpers.validateEmail(req.body.email)) {
    errors.push('Por favor ingresa un correo valido!');
    next();
    return;
  }

  var sqlQuery = `SELECT * FROM users WHERE user_email = ? AND user_pass = MD5(?)`;
  var values = [req.body.email, req.body.psw];

  db.query(sqlQuery, values, function (err, results, fields) {

    if (err) {
      errors.push(err.message);
      next();
      return;
    }

    if (results.length == 1) {
      req.session.authorised = true;
      req.session.fname = results[0].user_fname
      res.redirect('/');
      return;
    } else {
      errors.push('El usuario o la contraseña no son validos.');
      next();
    }

  });

});

router.post('/login', function (req, res, next) {

  res.statusCode = 401;

  res.render('login', {
    title: 'Login',
    messages: errors
  });

  errors = [];

});

router.get('/exit', function (req, res, next) {

  req.session.destroy(function (err) {
    res.redirect('/');
  });

});

module.exports = router;