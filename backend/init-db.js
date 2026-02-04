/* eslint-disable no-process-exit */
const db = require('./db');
db.initialize()
  .then(() => {
    console.log('Database initialized successfully.');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
