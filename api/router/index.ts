import {
    authUser,
    createRecoveryCodes,
    createUser,
    ejectUser,
    getUser,
    hasRecoveryKey,
} from 'api/controller'
import { Router } from 'express'

const router = Router()
router.get('/user', getUser)
router.post('/user', createUser)
router.post('/user/auth', authUser)
router.post('/user/eject', ejectUser)

router.get('/user/recovery-codes', hasRecoveryKey)
router.post('/user/recovery-codes', createRecoveryCodes)
export default router
