import bcrypt from 'bcrypt'

export default async (password: string): Promise<string | null> => {
    try {
        const salt = await bcrypt.genSalt()
        const hash = await bcrypt.hash(password, salt)
        return hash
    } catch (error) {
        console.log('Error while encrypting password')
        return null
    }
}
