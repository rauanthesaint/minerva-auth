// HTTP Status Code Constants
export const HTTP_STATUS = {
    SUCCESS: {
        OK: 200,
        CREATED: 201,
        ACCEPTED: 202,
    },

    CLIENT_ERROR: {
        BAD_REQUEST: 400,
        UNAUTHORIZED: 401,
        FORBIDDEN: 403,
        NOT_FOUND: 404,
        CONFLICT: 409,
        TOO_MANY_REQUESTS: 429,
    },

    SERVER_ERROR: {
        INTERNAL_SERVER_ERROR: 500,
    },
} as const

// Description of the status code for logging
export const HTTP_STATUS_MESSAGES = {
    [HTTP_STATUS.SUCCESS.OK]: 'OK',
    [HTTP_STATUS.SUCCESS.CREATED]: 'Created',
    [HTTP_STATUS.SUCCESS.ACCEPTED]: 'Accepted',

    [HTTP_STATUS.CLIENT_ERROR.BAD_REQUEST]: 'Bad Request',
    [HTTP_STATUS.CLIENT_ERROR.UNAUTHORIZED]: 'Unauthorized',
    [HTTP_STATUS.CLIENT_ERROR.FORBIDDEN]: 'Forbidden',
    [HTTP_STATUS.CLIENT_ERROR.NOT_FOUND]: 'Not Found',
    [HTTP_STATUS.CLIENT_ERROR.CONFLICT]: 'Conflict',

    [HTTP_STATUS.SERVER_ERROR.INTERNAL_SERVER_ERROR]: 'Internal Server Error',
} as const

// Getting messages for status codes
export const getStatusMessage = (status: number): string => {
    return (
        HTTP_STATUS_MESSAGES[status as keyof typeof HTTP_STATUS_MESSAGES] ||
        'Unknown Status'
    )
}
