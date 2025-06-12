import { User, UserRequiredFields } from 'api/domain/entities/user.entity'
import {
    OTP,
    CreateOTP,
    VerifyOTPRequest,
    ActiveOTP,
    OTPType,
} from 'api/domain/entities/user.entity'
import { IUserRepository } from 'api/domain/interfaces/repositories/userRepository.interface'
import DatabaseManager from 'api/infrastructure/database/manager/database.manager'

export default class UserRepository implements IUserRepository {
    constructor(private DatabaseManager: DatabaseManager) {}

    // ========== EXISTING USER METHODS ==========

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

    // Добавить эти методы в UserRepository класс

    // ========== RECOVERY CODES METHODS ==========

    async saveRecoveryCodesToDatabase(
        userId: number,
        codes: Array<{ code: string; hash: string }>
    ): Promise<void> {
        // Удаляем все старые неиспользованные recovery коды пользователя
        await this.DatabaseManager.query(
            'DELETE FROM recovery_codes WHERE user_id = $1 AND is_used = FALSE',
            [userId]
        )

        // Создаем VALUES строку для bulk insert
        const values = codes
            .map((_, index) => {
                const paramOffset = index * 5 + 2 // +2 потому что $1 уже занят userId
                return `($1, ${paramOffset}, ${paramOffset + 1}, ${
                    paramOffset + 2
                }, ${paramOffset + 3})`
            })
            .join(', ')

        // Создаем массив параметров
        const params: any[] = [userId]
        codes.forEach((codeData, index) => {
            params.push(
                codeData.code,
                codeData.hash,
                `Recovery code #${index + 1}`,
                new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // Передаем Date объект напрямую
            )
        })

        const query = `
        INSERT INTO recovery_codes (user_id, code, code_hash, description, expires_at) 
        VALUES ${values}
    `

        await this.DatabaseManager.query(query, params)
    }

    async getRecoveryCodes(userId: number): Promise<
        Array<{
            id: number
            code: string
            description: string
            created_at: Date
            expires_at: Date | null
            is_used: boolean
            used_at: Date | null
        }>
    > {
        const { rows } = await this.DatabaseManager.query(
            `SELECT id, code, description, created_at, expires_at, is_used, used_at 
         FROM recovery_codes 
         WHERE user_id = $1 
         ORDER BY created_at ASC`,
            [userId]
        )

        return rows.map((row) => ({
            id: row.id,
            code: row.code,
            description: row.description,
            created_at: row.created_at,
            expires_at: row.expires_at,
            is_used: row.is_used,
            used_at: row.used_at,
        }))
    }

    async getActiveRecoveryCodes(userId: number): Promise<
        Array<{
            id: number
            code: string
            description: string
            created_at: Date
            expires_at: Date | null
        }>
    > {
        const { rows } = await this.DatabaseManager.query(
            `SELECT id, code, description, created_at, expires_at 
         FROM recovery_codes 
         WHERE user_id = $1 AND is_used = FALSE 
         AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
         ORDER BY created_at ASC`,
            [userId]
        )

        return rows.map((row) => ({
            id: row.id,
            code: row.code,
            description: row.description,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }))
    }

    async findRecoveryCodeByCode(code: string): Promise<{
        id: number
        user_id: number
        code: string
        code_hash: string
        is_used: boolean
        expires_at: Date | null
    } | null> {
        const { rows } = await this.DatabaseManager.query(
            `SELECT id, user_id, code, code_hash, is_used, expires_at 
         FROM recovery_codes 
         WHERE code = $1`,
            [code]
        )

        if (rows.length === 0) {
            return null
        }

        return {
            id: rows[0].id,
            user_id: rows[0].user_id,
            code: rows[0].code,
            code_hash: rows[0].code_hash,
            is_used: rows[0].is_used,
            expires_at: rows[0].expires_at,
        }
    }

    async useRecoveryCode(
        id: number,
        ipAddress: string,
        userAgent: string
    ): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            `UPDATE recovery_codes 
         SET is_used = TRUE, 
             used_at = CURRENT_TIMESTAMP, 
             used_ip = $2, 
             used_user_agent = $3,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND is_used = FALSE`,
            [id, ipAddress, userAgent]
        )

        return (rowCount ?? 0) > 0
    }

    async validateRecoveryCode(code: string): Promise<{
        isValid: boolean
        userId?: number
        codeId?: number
        reason?: string
    }> {
        const recoveryCode = await this.findRecoveryCodeByCode(code)

        if (!recoveryCode) {
            return {
                isValid: false,
                reason: 'Recovery code not found',
            }
        }

        if (recoveryCode.is_used) {
            return {
                isValid: false,
                reason: 'Recovery code already used',
            }
        }

        if (recoveryCode.expires_at && new Date() > recoveryCode.expires_at) {
            return {
                isValid: false,
                reason: 'Recovery code expired',
            }
        }

        return {
            isValid: true,
            userId: recoveryCode.user_id,
            codeId: recoveryCode.id,
        }
    }

    async getRecoveryCodeStats(userId: number): Promise<{
        total: number
        used: number
        active: number
        expired: number
    }> {
        const { rows } = await this.DatabaseManager.query(
            `SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN is_used = TRUE THEN 1 END) as used,
            COUNT(CASE WHEN is_used = FALSE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) THEN 1 END) as active,
            COUNT(CASE WHEN is_used = FALSE AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP THEN 1 END) as expired
         FROM recovery_codes 
         WHERE user_id = $1`,
            [userId]
        )

        return {
            total: parseInt(rows[0].total),
            used: parseInt(rows[0].used),
            active: parseInt(rows[0].active),
            expired: parseInt(rows[0].expired),
        }
    }

    async regenerateRecoveryCodes(
        userId: number,
        newCodes: Array<{ code: string; hash: string }>
    ): Promise<{
        oldCodesRemoved: number
        newCodesCreated: number
    }> {
        // Подсчитываем сколько старых кодов удалим
        const { rows: countRows } = await this.DatabaseManager.query(
            'SELECT COUNT(*) as count FROM recovery_codes WHERE user_id = $1 AND is_used = FALSE',
            [userId]
        )
        const oldCodesCount = parseInt(countRows[0].count)

        // Сохраняем новые коды (метод автоматически удалит старые)
        await this.saveRecoveryCodesToDatabase(userId, newCodes)

        return {
            oldCodesRemoved: oldCodesCount,
            newCodesCreated: newCodes.length,
        }
    }

    async cleanupExpiredRecoveryCodes(): Promise<number> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM recovery_codes WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP'
        )
        return rowCount ?? 0
    }

    async cleanupUsedRecoveryCodes(
        olderThanDays: number = 30
    ): Promise<number> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM recovery_codes WHERE is_used = TRUE AND used_at < CURRENT_TIMESTAMP - INTERVAL $1 DAY',
            [olderThanDays]
        )
        return rowCount ?? 0
    }

    async revokeAllRecoveryCodes(userId: number): Promise<number> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM recovery_codes WHERE user_id = $1 AND is_used = FALSE',
            [userId]
        )
        return rowCount ?? 0
    }

    // ========== RECOVERY CODE VERIFICATION HELPERS ==========

    async verifyRecoveryCodeHash(code: string, hash: string): Promise<boolean> {
        // Используем bcrypt для проверки хеша (как в системе паролей)
        const bcrypt = require('bcrypt')
        return await bcrypt.compare(code, hash)
    }

    async getRecoveryCodeUsageHistory(
        userId: number,
        limit: number = 10
    ): Promise<
        Array<{
            code: string
            description: string
            used_at: Date
            used_ip: string
            used_user_agent: string
        }>
    > {
        const { rows } = await this.DatabaseManager.query(
            `SELECT code, description, used_at, used_ip, used_user_agent 
         FROM recovery_codes 
         WHERE user_id = $1 AND is_used = TRUE 
         ORDER BY used_at DESC 
         LIMIT $2`,
            [userId, limit]
        )

        return rows.map((row) => ({
            code: row.code,
            description: row.description,
            used_at: row.used_at,
            used_ip: row.used_ip,
            used_user_agent: row.used_user_agent,
        }))
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

    // ========== NEW USER METHODS ==========

    async updateUser(
        id: number,
        updates: Partial<UserRequiredFields>
    ): Promise<User | null> {
        const updateFields = []
        const values = []
        let paramCount = 1

        if (updates.email) {
            updateFields.push(`email = $${paramCount++}`)
            values.push(updates.email)
        }
        if (updates.name) {
            updateFields.push(`name = $${paramCount++}`)
            values.push(updates.name)
        }
        if (updates.password) {
            updateFields.push(`password = $${paramCount++}`)
            values.push(updates.password)
        }

        if (updateFields.length === 0) {
            return this.findById(id)
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`)
        values.push(id)

        const { rows } = await this.DatabaseManager.query(
            `UPDATE users SET ${updateFields.join(
                ', '
            )} WHERE id = $${paramCount} RETURNING *`,
            values
        )

        return rows.length > 0 ? this.mapToUserEntity(rows[0]) : null
    }

    async deleteUser(id: number): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM users WHERE id = $1',
            [id]
        )
        return (rowCount ?? 0) > 0
    }

    async updatePassword(id: number, hashedPassword: string): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [hashedPassword, id]
        )
        return (rowCount ?? 0) > 0
    }

    async updateEmail(id: number, email: string): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'UPDATE users SET email = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [email, id]
        )
        return (rowCount ?? 0) > 0
    }

    async verifyEmail(id: number): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'UPDATE users SET email_verified = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [id]
        )
        return (rowCount ?? 0) > 0
    }

    async existsByEmail(email: string): Promise<boolean> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT 1 FROM users WHERE email = $1 LIMIT 1',
            [email]
        )
        return rows.length > 0
    }

    async existsById(id: number): Promise<boolean> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT 1 FROM users WHERE id = $1 LIMIT 1',
            [id]
        )
        return rows.length > 0
    }

    async findUsers(limit: number = 50, offset: number = 0): Promise<User[]> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
            [limit, offset]
        )
        return rows.map((row) => this.mapToUserEntity(row))
    }

    async findUsersByName(name: string): Promise<User[]> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM users WHERE name ILIKE $1 ORDER BY name',
            [`%${name}%`]
        )
        return rows.map((row) => this.mapToUserEntity(row))
    }

    async searchUsers(query: string): Promise<User[]> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM users WHERE name ILIKE $1 OR email ILIKE $1 ORDER BY name',
            [`%${query}%`]
        )
        return rows.map((row) => this.mapToUserEntity(row))
    }

    // ========== OTP METHODS ==========

    async createOTP(otp: CreateOTP): Promise<OTP> {
        const {
            user_id,
            code,
            type,
            email,
            phone,
            expires_at,
            max_attempts = 3,
        } = otp

        // Сначала инвалидируем все активные OTP этого типа для пользователя
        await this.invalidateUserOTPs(user_id, type)

        const { rows } = await this.DatabaseManager.query(
            `INSERT INTO otp_codes (user_id, code, type, email, phone, expires_at, max_attempts)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [user_id, code, type, email, phone, expires_at, max_attempts]
        )

        if (rows.length === 0) {
            throw new Error('Failed to create OTP')
        }

        return this.mapToOTPEntity(rows[0])
    }

    async findActiveOTP(
        userId: number,
        code: string,
        type: OTPType
    ): Promise<ActiveOTP | null> {
        const { rows } = await this.DatabaseManager.query(
            `SELECT id, user_id, code, type, email, expires_at, attempts, max_attempts
             FROM otp_codes 
             WHERE user_id = $1 AND code = $2 AND type = $3 
               AND is_used = FALSE AND expires_at > CURRENT_TIMESTAMP 
               AND attempts < max_attempts
             ORDER BY created_at DESC LIMIT 1`,
            [userId, code, type]
        )

        return rows.length > 0 ? (rows[0] as ActiveOTP) : null
    }

    async findOTPById(id: number): Promise<OTP | null> {
        const { rows } = await this.DatabaseManager.query(
            'SELECT * FROM otp_codes WHERE id = $1',
            [id]
        )
        return rows.length > 0 ? this.mapToOTPEntity(rows[0]) : null
    }

    async verifyOTP(request: VerifyOTPRequest): Promise<{
        isValid: boolean
        otp?: ActiveOTP
        attemptsLeft?: number
    }> {
        const otp = await this.findActiveOTP(
            request.user_id,
            request.code,
            request.type
        )

        if (!otp) {
            return { isValid: false }
        }

        // Проверяем код
        if (otp.code === request.code) {
            return {
                isValid: true,
                otp,
                attemptsLeft: otp.max_attempts - otp.attempts,
            }
        } else {
            // Увеличиваем счетчик попыток
            const newAttempts = await this.incrementOTPAttempts(otp.id)
            return {
                isValid: false,
                attemptsLeft: otp.max_attempts - newAttempts,
            }
        }
    }

    async markOTPAsUsed(id: number): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'UPDATE otp_codes SET is_used = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [id]
        )
        return (rowCount ?? 0) > 0
    }

    async incrementOTPAttempts(id: number): Promise<number> {
        const { rows } = await this.DatabaseManager.query(
            'UPDATE otp_codes SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING attempts',
            [id]
        )
        return rows.length > 0 ? rows[0].attempts : 0
    }

    async invalidateUserOTPs(userId: number, type?: OTPType): Promise<number> {
        const query = type
            ? 'UPDATE otp_codes SET is_used = TRUE WHERE user_id = $1 AND type = $2 AND is_used = FALSE'
            : 'UPDATE otp_codes SET is_used = TRUE WHERE user_id = $1 AND is_used = FALSE'

        const params = type ? [userId, type] : [userId]
        const { rowCount } = await this.DatabaseManager.query(query, params)
        return rowCount ?? 0
    }

    async cleanupExpiredOTPs(): Promise<number> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM otp_codes WHERE expires_at < CURRENT_TIMESTAMP OR is_used = TRUE'
        )
        return rowCount ?? 0
    }

    async deleteOTP(id: number): Promise<boolean> {
        const { rowCount } = await this.DatabaseManager.query(
            'DELETE FROM otp_codes WHERE id = $1',
            [id]
        )
        return (rowCount ?? 0) > 0
    }

    async getUserOTPs(
        userId: number,
        type?: OTPType,
        includeExpired: boolean = false
    ): Promise<OTP[]> {
        let query = 'SELECT * FROM otp_codes WHERE user_id = $1'
        const params: any[] = [userId]
        let paramCount = 2

        if (type) {
            query += ` AND type = $${paramCount++}`
            params.push(type)
        }

        if (!includeExpired) {
            query += ' AND expires_at > CURRENT_TIMESTAMP'
        }

        query += ' ORDER BY created_at DESC'

        const { rows } = await this.DatabaseManager.query(query, params)
        return rows.map((row) => this.mapToOTPEntity(row))
    }

    async getActiveOTPsForUser(userId: number): Promise<OTP[]> {
        const { rows } = await this.DatabaseManager.query(
            `SELECT * FROM otp_codes 
             WHERE user_id = $1 AND is_used = FALSE AND expires_at > CURRENT_TIMESTAMP
             ORDER BY created_at DESC`,
            [userId]
        )
        return rows.map((row) => this.mapToOTPEntity(row))
    }

    async getOTPCountForUser(
        userId: number,
        type: OTPType,
        timeframe?: Date
    ): Promise<number> {
        let query =
            'SELECT COUNT(*) as count FROM otp_codes WHERE user_id = $1 AND type = $2'
        const params: any[] = [userId, type]

        if (timeframe) {
            query += ' AND created_at >= $3'
            params.push(timeframe)
        }

        const { rows } = await this.DatabaseManager.query(query, params)
        return parseInt(rows[0].count)
    }

    async canSendOTP(
        userId: number,
        type: OTPType
    ): Promise<{
        canSend: boolean
        reason?: string
        nextAllowedAt?: Date
    }> {
        // Проверяем количество OTP за последние 24 часа
        const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000)
        const dailyCount = await this.getOTPCountForUser(
            userId,
            type,
            last24Hours
        )

        if (dailyCount >= 10) {
            // Максимум 10 OTP в день
            return {
                canSend: false,
                reason: 'Daily limit exceeded',
                nextAllowedAt: new Date(
                    last24Hours.getTime() + 24 * 60 * 60 * 1000
                ),
            }
        }

        // Проверяем последний OTP (cooldown 60 секунд)
        const { rows } = await this.DatabaseManager.query(
            `SELECT created_at FROM otp_codes 
             WHERE user_id = $1 AND type = $2 
             ORDER BY created_at DESC LIMIT 1`,
            [userId, type]
        )

        if (rows.length > 0) {
            const lastOTP = new Date(rows[0].created_at)
            const cooldownEnd = new Date(lastOTP.getTime() + 60 * 1000) // 60 секунд

            if (new Date() < cooldownEnd) {
                return {
                    canSend: false,
                    reason: 'Cooldown period active',
                    nextAllowedAt: cooldownEnd,
                }
            }
        }

        return { canSend: true }
    }

    // ========== COMBINED METHODS ==========

    async findUserWithActiveOTP(
        userId: number,
        type: OTPType
    ): Promise<{
        user: User | null
        otp: OTP | null
    }> {
        const user = await this.findById(userId)
        const otps = await this.getUserOTPs(userId, type, false)
        const activeOTP = otps.find(
            (otp) => !otp.is_used && otp.expires_at > new Date()
        )

        return {
            user,
            otp: activeOTP || null,
        }
    }

    async createUserWithVerification(user: UserRequiredFields): Promise<{
        user: User
        otp: OTP
    }> {
        const newUser = await this.createUser(user)

        // Генерируем 6-значный код
        const code = Math.floor(100000 + Math.random() * 900000).toString()
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000) // 10 минут

        const otp = await this.createOTP({
            user_id: newUser.id,
            code,
            type: OTPType.EMAIL_VERIFICATION,
            email: newUser.email,
            expires_at: expiresAt,
            max_attempts: 3, // ДОБАВЛЕНО: обязательное поле
        })

        return { user: newUser, otp }
    }
    async confirmEmailWithOTP(
        userId: number,
        code: string
    ): Promise<{
        success: boolean
        user?: User
        message: string
    }> {
        const verification = await this.verifyOTP({
            user_id: userId,
            code,
            type: OTPType.EMAIL_VERIFICATION,
        })

        if (!verification.isValid || !verification.otp) {
            return {
                success: false,
                message: verification.attemptsLeft
                    ? `Invalid code. ${verification.attemptsLeft} attempts left.`
                    : 'Invalid or expired code.',
            }
        }

        // Подтверждаем email и помечаем OTP как использованный
        await Promise.all([
            this.verifyEmail(userId),
            this.markOTPAsUsed(verification.otp.id),
        ])

        const user = await this.findById(userId)

        return {
            success: true,
            user: user!,
            message: 'Email verified successfully',
        }
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

    async resetPasswordWithOTP(
        email: string,
        code: string,
        newPassword: string
    ): Promise<{
        success: boolean
        user?: User
        message: string
    }> {
        const user = await this.findByEmail(email)
        if (!user) {
            return {
                success: false,
                message: 'User not found',
            }
        }

        const verification = await this.verifyOTP({
            user_id: user.id,
            code,
            type: OTPType.PASSWORD_RESET,
        })

        if (!verification.isValid || !verification.otp) {
            return {
                success: false,
                message: verification.attemptsLeft
                    ? `Invalid code. ${verification.attemptsLeft} attempts left.`
                    : 'Invalid or expired code.',
            }
        }

        // Обновляем пароль и помечаем OTP как использованный
        await Promise.all([
            this.updatePassword(user.id, newPassword),
            this.markOTPAsUsed(verification.otp.id),
        ])

        const updatedUser = await this.findById(user.id)

        return {
            success: true,
            user: updatedUser!,
            message: 'Password reset successfully',
        }
    }

    // ========== UTILITY METHODS ==========

    async getUserStats(userId: number): Promise<{
        totalOTPsSent: number
        totalOTPsVerified: number
        lastLoginAt?: Date
        accountCreatedAt: Date
        emailVerified: boolean
    }> {
        const user = await this.findById(userId)
        if (!user) {
            throw new Error('User not found')
        }

        const { rows: otpStats } = await this.DatabaseManager.query(
            `SELECT 
                COUNT(*) as total_sent,
                COUNT(CASE WHEN is_used = TRUE THEN 1 END) as total_verified
             FROM otp_codes WHERE user_id = $1`,
            [userId]
        )

        return {
            totalOTPsSent: parseInt(otpStats[0].total_sent),
            totalOTPsVerified: parseInt(otpStats[0].total_verified),
            accountCreatedAt: user.created_at,
            emailVerified: true, // Предполагаем что поле есть в БД
        }
    }

    async getUserSecurityInfo(userId: number): Promise<{
        failedLoginAttempts: number
        lastFailedLoginAt?: Date
        accountLocked: boolean
        lockExpiresAt?: Date
    }> {
        // Базовая реализация - расширить по необходимости
        return {
            failedLoginAttempts: 0,
            accountLocked: false,
        }
    }

    async cleanupUserData(userId: number): Promise<{
        otpsRemoved: number
        userDeleted: boolean
    }> {
        const { rowCount: otpsRemoved } = await this.DatabaseManager.query(
            'DELETE FROM otp_codes WHERE user_id = $1',
            [userId]
        )

        const userDeleted = await this.deleteUser(userId)

        return {
            otpsRemoved: otpsRemoved ?? 0,
            userDeleted,
        }
    }

    // ========== MAPPERS ==========

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

    private mapToOTPEntity(data: any): OTP {
        return {
            id: data.id,
            user_id: data.user_id,
            code: data.code,
            type: data.type,
            email: data.email,
            phone: data.phone,
            expires_at: data.expires_at,
            is_used: data.is_used,
            attempts: data.attempts,
            max_attempts: data.max_attempts,
            created_at: data.created_at,
            updated_at: data.updated_at,
        }
    }
}
