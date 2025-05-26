import winston from 'winston';

// Initialize logging with Python-like format
const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console()
    ]
});

export default logger; 