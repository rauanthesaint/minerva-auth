import nodemailer, { SendMailOptions } from 'nodemailer'
import ConfigService from 'api/config/config.class'

const configService = new ConfigService()
const SENDER = configService.get('TRANSPORTER_EMAIL')
const transporter = nodemailer.createTransport({
    host: 'smtp.mail.ru',
    port: 465,
    secure: true,
    auth: {
        user: SENDER,
        pass: configService.get('TRANSPORTER_PASS'),
    },
})

export const sendMail = (recipient: string, text: string, subject: string) => {
    const mailOptions: SendMailOptions = {
        from: SENDER,
        to: recipient,
        subject,
        text,
    }
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.error('[Mail Service]: ', error)
        }
        console.log('[Mail Service]: ', info.response)
    })
}
