import { CorsOptions } from 'cors'
import ConfigService from './config/config.class'
import DatabaseManager from './infrastructure/database/manager/database.manager'
import UserRepository from './infrastructure/database/repositories/user.repository'
import UserService from './services/user.service'
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { userRoutes } from './router/user.routes'
import { authRoutes } from './router/auth.routes'

const configService = new ConfigService()

const corsOptions: CorsOptions = {
    origin:
        configService.get('ENVIRONMENT') === 'production'
            ? configService.get('CORS_ORIGIN')
            : 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: 'Content-Type, Authorization, X-Requested-With',
    maxAge: 86400, // 30 days,
}

const databaseManager = new DatabaseManager(configService.get('DATABASE_URL'))
databaseManager.connect()

const userRepository = new UserRepository(databaseManager)
const userService = new UserService(userRepository)

const application = express()

application.use(cors(corsOptions))
application.use(cookieParser())
application.use(express.json())
application.use('/api/v1', userRoutes(userService))
application.use('/api/v1', authRoutes())

const PORT = configService.get('PORT') || 5000

application.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
})
