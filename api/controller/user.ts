import pool from 'api/database/config'
import encrypt from 'api/utils/encrypt'
import { InternalServerError } from 'api/utils/responses'
import { MAX_AGE, createToken, decodeToken } from 'api/utils/token'
import { Request, Response } from 'express'
import bcrypt from 'bcrypt'
import { generateKeys } from 'api/utils/generateKeys'

export const getUser = async (request: Request, response: Response) => {
    try {
        const token = request.cookies['jwt']

        if (!token) {
            response
                .status(401)
                .json({ message: 'Unauthorized: No token provided' })
            return
        }
        const id = decodeToken(token)
        if (!id) {
            response.status(401).json({ message: 'Invalid token' })
            return
        }

        const result = await pool.query(`SELECT * FROM users WHERE id=$1`, [id])

        if (result.rowCount === 0) {
            response.status(404).json({
                message: 'User Not Found',
            })
            return
        }
        const { password, ...other } = result.rows[0]
        response.status(200).json({
            message: `HTTP GET request completed successfully`,
            data: other,
        })
    } catch (error) {
        InternalServerError(response, error)
    }
}

export const createUser = async (request: Request, response: Response) => {
    try {
        const { email, password } = request.body
        const hash = await encrypt(password)

        if (typeof hash !== 'string') {
            InternalServerError(response)
        }

        const result = await pool.query(
            `INSERT INTO users (email, password) 
            VALUES ($1, $2) RETURNING *;`,
            [email, hash]
        )

        const id = result.rows[0].id
        const token = createToken(id)
        response.cookie('jwt', token, {
            path: '/',
            maxAge: MAX_AGE * 1000,
            httpOnly: true,
        })

        response.status(201).json({
            message: 'HTTP POST request completed successfully',
        })
    } catch (error) {
        InternalServerError(response, error)
    }
}

export const authUser = async (request: Request, response: Response) => {
    try {
        const { email, password } = request.body
        const result = await pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [email]
        )

        if (result.rowCount === 0) {
            response.status(404).json({
                message: 'User Not Found',
            })
            return
        }

        const isValid = await bcrypt.compare(password, result.rows[0].password)

        if (!isValid) {
            response.status(400).json({
                message: 'HTTP POST request failed with status code 404',
            })
            return
        }

        const id = result.rows[0].id
        const token = createToken(id)
        response.cookie('jwt', token, {
            path: '/',
            maxAge: MAX_AGE * 1000,
            httpOnly: true,
        })

        response.status(200).json({
            message: 'HTTP POST request completed successfully',
        })
    } catch (error) {
        InternalServerError(response, error)
    }
}

export const ejectUser = async (request: Request, response: Response) => {
    try {
        response.clearCookie('jwt', { path: '/', maxAge: 0 })
        response.status(200).json({
            message: 'HTTP POST request completed successfully',
        })
    } catch (error) {
        InternalServerError(response, error)
    }
}

export const hasRecoveryKey = async (request: Request, response: Response) => {
    try {
        const token = request.cookies['jwt']
        if (!token) {
            response
                .status(401)
                .json({ message: 'Unauthorized: No token provided' })
            return
        }
        const id = decodeToken(token)
        if (!id) {
            response.status(401).json({ message: 'Invalid token' })
            return
        }

        const result = await pool.query(
            `SELECT has_recovery_keys FROM users WHERE id = $1`,
            [id]
        )
        const flag = result.rowCount === 0
        response.status(200).json({
            message: 'HTTP GET request completed successfully',
            data: flag,
        })
    } catch (error) {
        InternalServerError(response, error)
    }
}

export const createRecoveryCodes = async (
    request: Request,
    response: Response
) => {
    try {
        const token = request.cookies['jwt']
        if (!token) {
            response
                .status(401)
                .json({ message: 'Unauthorized: No token provided' })
            return
        }

        const userId = decodeToken(token)
        if (!userId) {
            response.status(401).json({ message: 'Invalid token' })
            return
        }

        const hash = generateKeys(userId)
        const client = await pool.connect()
        try {
            await client.query('BEGIN') // Start transaction

            const insertResult = await client.query(
                `
                INSERT INTO recovery_codes (user_id, hash)
                VALUES ($1, $2) 
                RETURNING *;
                `,
                [userId, hash]
            )

            await client.query(
                `
                UPDATE users
                SET has_recovery_keys = true
                WHERE id = $1;
                `,
                [userId]
            )

            await client.query('COMMIT') // Commit transaction

            response.status(201).json({
                message: 'Recovery key created successfully',
                data: insertResult.rows[0],
            })
        } catch (error) {
            await client.query('ROLLBACK') // Rollback on error
            throw error
        } finally {
            client.release()
        }
    } catch (error) {
        InternalServerError(response, error)
    }
}
