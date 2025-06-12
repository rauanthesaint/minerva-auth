export default class Logger {
    static error(where: string, message: string, statusCode: number) {
        console.error('Error')
        console.log({
            FROM: where,
            MESSAGE: message,
            STATUS_CODE: statusCode,
        })
    }
}
