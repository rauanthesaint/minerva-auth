import { User, UserRequiredFields } from 'api/domain/entities/user.entity'
import { IUserRepository } from 'api/domain/interfaces/repositories/userRepository.interface'
import DatabaseManager from 'api/infrastructure/database/manager/database.manager'

export default class UserRepository implements IUserRepository {
    constructor(private DatabaseManager: DatabaseManager) {}

    async findById(id: number): Promise<User | null> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM users WHERE id=$1',
            [id]
        )
        if (rows.length === 0) {
            return null
        }

        return this.mapToUserEntity(rows[0])
    }

    async findByEmail(email: string): Promise<User | null> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM users WHERE email=$1',
            [email]
        )
        if (rows.length === 0) {
            return null
        }

        return this.mapToUserEntity(rows[0])
    }

    async createUser(user: UserRequiredFields): Promise<User> {
        const { email, password, name } = user

        const { rows } = await this.DatabaseManager.query(
            `INSERT INTO users (email, password, name)
            VALUES ($1, $2, $3)
            RETURNING *`,
            [email, password, name]
        )

        if (rows.length === 0) {
            throw new Error('Failed to create user')
        }

        return this.mapToUserEntity(rows[0])
    }

    private mapToUserEntity(data: any): User {
        return {
            id: data.id,
            created_at: data.created_at,
            updated_at: data.updated_at,
            email: data.email,
            password: data.password,
            name: data.name,
        }
    }
}
