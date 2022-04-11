const tokenService    = require('../services/tokenService');

const checkTokenMiddleware = async (req, res, next) => {
  try {
    await tokenService.isTokenSignatureValid(req, res, next);
  } catch (e) {
    res.status(401).send('Token is not valid!');
  }
}

module.exports = {
  checkTokenMiddleware: checkTokenMiddleware,
}