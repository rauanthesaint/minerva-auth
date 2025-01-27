import ConfigService from 'api/config/config.class'
import { Pool } from 'pg'

const configService = new ConfigService()

const pool = new Pool({
    connectionString: configService.get('DATABASE_URL'),
    ssl: {
        rejectUnauthorized: false,
    },
})
pool.connect((error, client, release) => {
    if (error) {
        console.error('Error connecting to the database:', error)
    } else {
        console.log('Successfully connected to the database')
        release()
    }
})

export default pool
