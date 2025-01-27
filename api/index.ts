import cors from 'cors'
import express from 'express'
const app = express()

app.use(
    cors({
        origin: '*', // Adjust the origin as needed for security
        credentials: true,
        methods: 'PUT, POST, GET, DELETE, PATCH, OPTIONS',
        allowedHeaders: 'Content-Type',
        maxAge: 1800,
    })
)

app.get('/', (req, res) => {
    res.json({
        message: 'Hi',
    })
})

app.listen(3000, () => console.log('Server ready on port 3000'))

export default app
