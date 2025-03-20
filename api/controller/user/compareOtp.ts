import { Request, Response } from 'express'
import pool from 'api/database/config'
import {
    BadRequestError,
    InternalServerError,
    NotFoundError,
} from 'api/utils/server-errors'
import bcrypt from 'bcrypt'
import { createToken } from 'api/utils/token'
import { cookieOptions } from 'api/utils/cookieOptions'

export default async function verifyOTP(request: Request, response: Response) {
    try {
        const { email, otp } = request.body
        if (!email || !otp) {
            console.error('undefined')
            return BadRequestError(response)
        }

        const { rows, rowCount } = await pool.query(
            `SELECT otp_hash, expires_at, user_id FROM otp_verifications
             JOIN users ON otp_verifications.user_id = users.id
             WHERE users.email = $1
             ORDER BY expires_at DESC LIMIT 1`,
            [email]
        )

        if (rowCount === 0) return NotFoundError(response)

        const { otp_hash, expires_at, user_id } = rows[0]
        const expirationDate = new Date(expires_at + 'Z') // Добавляем "Z", чтобы сказать, что это UTC
        const currentDate = new Date()
        if (currentDate > expirationDate) {
            console.error('Expired')
            return BadRequestError(response)
        }

        const isValid = await bcrypt.compare(otp, otp_hash)
        if (!isValid) {
            console.error('Invalid')
            return BadRequestError(response)
        }

        await pool.query(`DELETE FROM otp_verifications WHERE otp_hash = $1`, [
            otp_hash,
        ])

        if (!user_id) return InternalServerError(response)
        const token = createToken(user_id)
        // Возвращаем ответ сервера
        // и создаем сессию пользователя
        response.cookie('jwt', token, cookieOptions)
        response.status(200).json({
            message: 'User authenticated successfully',
        })
    } catch (error) {
        return InternalServerError(response, error)
    }
}
