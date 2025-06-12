import { Router } from 'express'
import UserService from 'api/services/user.service'
import UserController from 'api/controllers/user.controller'

export const userRoutes = (userService: UserService): Router => {
    const router = Router()
    const controller = new UserController(userService)

    router.post('/user', controller.createUser.bind(controller))
    router.get('/user', controller.getUser.bind(controller))
    router.post('/auth', controller.authenticateUser.bind(controller))
    // router.patch("/users/:id");
    // router.delete("/users/:id");
    // router.put("/users/:id");

    return router
}
