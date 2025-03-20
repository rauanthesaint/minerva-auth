import { Request, Response } from 'express'
import pool from 'api/database/config'
import bcrypt from 'bcrypt'
import {
    BadRequestError,
    InternalServerError,
    NotFoundError,
} from 'api/utils/server-errors'
import { sendMail } from 'api/utils/mail-service'
import { generateOTP } from 'api/utils/one-time-password'
import encrypt from 'api/utils/encrypt'

export default async function authUser(request: Request, response: Response) {
    try {
        // Получаем данные из запроса и проверяем их на валидность
        // В случае несоответствия данных возвращаем ошибку 400
        const { email, password } = request.body
        if (!email || !password) return BadRequestError(response)

        const { rows, rowCount } = await pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [email]
        )
        if (rowCount === 0) {
            return NotFoundError(response)
        }

        const isValid = await bcrypt.compare(password, rows[0].password)
        if (!isValid) {
            return BadRequestError(response)
        }

        const userId = rows[0].id
        if (!userId) return InternalServerError(response)

        const otp = generateOTP()
        const otp_hash = await encrypt(otp)
        const otp_record = await pool.query(
            `INSERT INTO otp_verifications (user_id, otp_hash) VALUES ($1, $2) RETURNING *;`,
            [userId, otp_hash]
        )
        if (otp_record.rowCount === 0) return InternalServerError(response)
        sendMail(email, otp, 'Two-Step Verification')
        response.status(200).json({
            message: 'OTP sent successfully',
            data: otp_record.rows[0].expires_at,
        })
    } catch (error) {
        return InternalServerError(response, error)
    }
}
