import pool from 'api/database/config'
import { cookieOptions } from 'api/utils/cookieOptions'
import encrypt from 'api/utils/encrypt'
import { BadRequestError, InternalServerError } from 'api/utils/server-errors'
import { Request, Response } from 'express'
import { createToken } from 'api/utils/token'

// Notes: Добавить валидацию данных

export default async function createUser(
    request: Request,
    response: Response
): Promise<void> {
    try {
        // Получаем данные из запроса и проверяем их на валидность
        // В случае несоответствия данных возвращаем ошибку 400
        const { email, password } = request.body
        if (!email || !password) return BadRequestError(response)
        // Шифруем пароль. Если результат функции шифрования
        // не строка (null/undefined), запись в базу данных
        // не может быть выполнена и сервер возвращает ошибку
        const hash = await encrypt(password)
        if (!hash) return InternalServerError(response)
        // Записываем полученные данные в базу данных
        // и тем самым создаем учетную запись пользователя
        const { rows } = await pool.query(
            `INSERT INTO users (email, password) 
            VALUES ($1, $2) RETURNING *`,
            [email, hash]
        )
        // Если произойдет ошибка и аттрибут id не получит значение
        // дальнейшие действия не могут быть выполнены
        // и сервер вернет ошибку
        const userId = rows[0].id
        if (!userId) return InternalServerError(response)
        const token = createToken(userId)
        // Возвращаем ответ сервера
        // и создаем сессию пользователя
        response.cookie('jwt', token, cookieOptions)
        response.status(201).json({
            message: 'User created successfully',
        })
    } catch (error) {
        return InternalServerError(response, error)
    }
}
