import { InternalServerError } from 'api/utils/server-errors'
import { Request, Response } from 'express'

export default async function ejectUser(
    request: Request,
    response: Response
): Promise<void> {
    try {
        response.clearCookie('jwt', { path: '/', maxAge: 0 })
        response.status(200).json({
            message: 'User ejected successfully',
        })
    } catch (error) {
        return InternalServerError(response, error)
    }
}
