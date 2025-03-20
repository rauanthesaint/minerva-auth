import cors from 'cors'
import express from 'express'
import router from './router'
import { MAX_AGE } from './utils/token'
import cookieParser from 'cookie-parser'
const application = express()
application.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
        methods: 'PUT, POST, GET, DELETE, PATCH, OPTIONS',
        allowedHeaders: 'Content-Type',
        maxAge: MAX_AGE * 1000,
    })
)
application.use(express.json())
application.use(cookieParser())
application.use('/api', router)

application.listen(3001, () => console.log('Server ready on port 3001'))

export default application
