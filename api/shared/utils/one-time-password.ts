import crypto from 'crypto'

export const generateOTP = (length: number = 6): string => {
    if (length < 0) {
        throw new Error('OTP length must be greater than zero')
    }

    let result = ''
    const digits = '0123456789'

    for (let i = 0; i < length; i++) {
        const index = crypto.randomInt(0, digits.length)
        result += digits[index]
    }

    return result
}
