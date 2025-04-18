// server/utils/logger.js
/**
 * Centralized Winston logger setup.
 */
const winston = require('winston');
const { LOG_LEVEL, NODE_ENV } = require('../config/constants'); // Use centralized constants

const loggerFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: NODE_ENV !== 'production' }), // Show stack only in dev/test
  winston.format.splat(),
  winston.format.json() // Log structured JSON to file
);

// Define transports based on environment
const loggerTransports = [
  new winston.transports.Console({
    level: LOG_LEVEL, // Ensure console respects the configured level
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.printf(({ level, message, timestamp, ...metadata }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        // Simple metadata formatting for console
        if (metadata && Object.keys(metadata).length > 0) {
          // Avoid logging huge objects to console, shorten long strings
          const metaString = JSON.stringify(
            metadata,
            (key, value) =>
              typeof value === 'string' && value.length > 200
                ? value.substring(0, 200) + '...' // Truncate long strings
                : value instanceof Error // Ensure Error messages are logged
                  ? {
                      message: value.message,
                      stack:
                        NODE_ENV !== 'production' ? value.stack?.split('\n')[1]?.trim() : undefined,
                    } // Log error message and maybe first stack line
                  : value, // Keep other values as is
            2 // Indent for readability
          );
          // Only append metadata if it's not just an empty object or simple primitive already in message
          if (metaString !== '{}' && typeof metadata !== 'string' && typeof metadata !== 'number') {
            msg += ` ${metaString}`;
          }
        }
        return msg;
      })
    ),
    // Silence console transport during tests run via `NODE_ENV=test`
    silent: NODE_ENV === 'test',
  }),
];

// Add file transport if not in test environment
if (NODE_ENV !== 'test') {
  loggerTransports.push(
    new winston.transports.File({
      filename: 'server.log',
      level: LOG_LEVEL, // Ensure file respects the configured level
      format: loggerFormat, // Log full JSON to file
      maxsize: 5242880, // 5MB file size limit
      maxFiles: 5, // Keep up to 5 log files
      tailable: true,
    })
  );
  // Optional: Add a separate file for errors only
  // loggerTransports.push(
  //   new winston.transports.File({
  //     filename: 'server-error.log',
  //     level: 'error', // Log only 'error' level messages
  //     format: loggerFormat,
  //     maxsize: 5242880,
  //     maxFiles: 3,
  //   })
  // );
}

const logger = winston.createLogger({
  level: LOG_LEVEL, // Master level for the logger instance
  format: loggerFormat, // Default format (used by file transport)
  transports: loggerTransports,
  exitOnError: false, // Recommended practice: Don't exit on logger errors
});

logger.info(`Logger initialized with level: ${LOG_LEVEL}`);

module.exports = logger; // Export the configured logger instance
