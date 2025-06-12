import { Pool, PoolClient, QueryResult } from 'pg'
import { ConfigService } from 'api/config/config.class'

const configService = new ConfigService()

const isProduction = configService.get('ENVIRONMENT') === 'production'

class DatabaseManager {
    private pool: Pool

    constructor(connectionString: string) {
        this.pool = new Pool({
            connectionString,
            ssl: {
                rejectUnauthorized: isProduction, // For development purposes only; set to true in production
            },
        })

        this.pool.on('error', (err: Error) => {
            console.error('Unexpected error on idle client', err)
        })
    }

    //** Проверяет соединение с базой данных */
    async connect(): Promise<boolean> {
        let client: PoolClient | null = null
        try {
            client = await this.pool.connect()
            console.log('Successfully connected to the database')
            return true
        } catch (error) {
            console.error(`Error connecting to the database: ${error}`)
            throw error
        } finally {
            if (client) {
                client.release()
            }
        }
    }

    //** Закрывает все соединения с базой данных */
    async close(): Promise<void> {
        try {
            await this.pool.end()
            console.log('Database connection pool has been closed')
        } catch (error) {
            console.error(`Error closing database connections: ${error}`)
            throw error
        }
    }

    //** Выполняет SQL-запрос */
    async query(text: string, params: any[] = []): Promise<QueryResult<any>> {
        const start = Date.now()
        try {
            const result = await this.pool.query(text, params)
            const duration = Date.now() - start
            console.log(
                `Executed query: ${text} with params: ${JSON.stringify(
                    params
                )} - ${duration}ms`
            )
            return result
        } catch (error) {
            console.error(`Error executing query: ${text}`, error)
            throw error
        }
    }
}
export default DatabaseManager
