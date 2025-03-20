import { Response } from 'express'
export const InternalServerError = (response: Response, error?: unknown) => {
    if (error) {
        console.error('Error: ', error)
    }
    response.status(500).json({
        message: 'Internal Server Error',
    })
}

export const UnauthorizedAccessError = (response: Response) => {
    const message: string = 'Unauthorized Access Error'
    response.status(401).json({
        message,
    })
}

export const NotFoundError = (response: Response) => {
    const message: string = 'Not Found Error'
    response.status(404).json({
        message,
    })
}

export const BadRequestError = (response: Response) => {
    response.status(400).json({
        message: 'Bad request',
    })
}
