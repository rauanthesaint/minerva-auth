import { sha256 } from 'js-sha256'
import { randomInt } from 'crypto'

function getSecureRandomNumber(min: number, max: number): number {
    return randomInt(min, max + 1)
}

export const generateKeys = (secret: string): string => {
    const hashArray: string[] = []
    for (let i = 0; i < 4; i++) {
        hashArray.push(
            sha256(secret + getSecureRandomNumber(1000, 9999).toString())
                .replace(/(.{16})/g, '$1-')
                .replace(/-$/, '')
        )
    }
    return hashArray.join('-')
}
