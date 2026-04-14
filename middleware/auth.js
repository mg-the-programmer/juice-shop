const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  throw new Error('JWT_SECRET is not set');
}

module.exports = (req, res, next) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });

    if (!decoded?.sub) return res.status(401).json({ error: 'Invalid token' });
    req.userId   = decoded.sub;
    req.userRole = decoded.role ?? 'user';
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  next();
};
