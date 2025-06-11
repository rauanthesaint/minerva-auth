import pool from 'api/database/config'
import {
    InternalServerError,
    NotFoundError,
    UnauthorizedAccessError,
} from 'api/utils/server-errors'
import { Request, Response } from 'express'
import { decodeToken } from 'api/utils/token'

/**
 * Handles an API request to retrieve user data based on a JSON Web Token (JWT).
 *
 * @param {Request} request - The incoming request object.
 * @param {Response} response - The outgoing response object.
 * @returns {Promise<void>} A promise that resolves when the request is handled.
 */
export default async function getUserData(
    request: Request,
    response: Response
): Promise<void> {
    try {
        // Extract JWT from cookies
        const token = request.cookies['jwt']
        if (!token) return UnauthorizedAccessError(response)

        // Decode the JWT and extract the user ID
        const userId = decodeToken(token)
        if (!userId) return UnauthorizedAccessError(response)

        // Retrieve user data from the database
        const { rows, rowCount } = await pool.query(
            'SELECT * FROM users WHERE id = $1',
            [userId]
        )
        if (rowCount === 0) return NotFoundError(response)

        // Exclude sensitive data before responding
        const { password, ...userData } = rows[0]

        // Send response
        response.status(200).json({
            message: 'User data successfully retrieved.',
            data: userData,
        })
    } catch (error) {
        return InternalServerError(response, error)
    }
}
