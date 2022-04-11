const express = require('express');
const bodyParser = require('body-parser');

const tokenService    = require('../services/tokenService');
const tokenMiddleware = require('../middlewares/tokenMIddleware');
const jwtMiddleware   = require('../middlewares/jwtMiddleware'); 

const tokenRoutes = express.Router();

// create application/json parser
var jsonParser = bodyParser.json();
 
// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });
  
tokenRoutes.post('/token', jsonParser, async (req, res) => {
  try {
      await tokenService.checkUserToken(req, res);
  } catch (e) {
    res.status(400).send('Error fetching unique token!');
  }
});

tokenRoutes.post('/credentials', jsonParser, tokenMiddleware.checkTokenMiddleware, async (req, res) => {
  try {
    await tokenService.fetchOrCreateUserCredentials(req, res);
  } catch (e) {
    console.log(e);
    res.status(400).send('Error creating credentials!');
  }
});

tokenRoutes.post('/action', jsonParser, tokenMiddleware.checkTokenMiddleware, async (req, res, next) => {
  await tokenService.performAction(req, res);
  res.json('Action performed');
});

tokenRoutes.post('/auth-action/:id', jsonParser, jwtMiddleware.checkIfJwtIsValid, (req, res, next) => {
  res.json('Auth Action performed');
});

module.exports = tokenRoutes;