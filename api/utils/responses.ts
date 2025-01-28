import { Response } from 'express'
export const InternalServerError = (response: Response, cause?: unknown) => {
    if (cause) {
        console.error('Error: ', cause)
    }
    response.status(500).json({
        message: 'Internal Server Error',
    })
}
