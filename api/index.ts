import cors from 'cors'
import express from 'express'
import pool from './database/config'
const application = express()

application.use(
    cors({
        origin: '*', // Adjust the origin as needed for security
        credentials: true,
        methods: 'PUT, POST, GET, DELETE, PATCH, OPTIONS',
        allowedHeaders: 'Content-Type',
        maxAge: 1800,
    })
)

application.get('/', async (req, res) => {
    const result = await pool.query(`SELECT * FROM users`)
    res.status(200).json({
        message: 'Users fetched successfully',
        data: result.rows,
    })
})

application.listen(3000, () => console.log('Server ready on port 3000'))

export default application
