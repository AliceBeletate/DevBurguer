import * as Yup from 'yup';
import User from '../models/users';
import jwt from 'jsonwebtoken';
import authConfig from '../../config/auth';

class SessionController {
    async store(request, response) {
        const schema = Yup.object().shape({
            // name: Yup.string().required(),
            email: Yup.string().email().required(),
            password: Yup.string().min(6).required(),
            // admin: Yup.boolean(),
        });



        const isValid = await schema.isValid(request.body);

        const emailOrPasswordIncorrect = () => {
            response.status(401).json({ error: 'Usuário ou senha incorretos.' });
        }

        if (!isValid) {
            return emailOrPasswordIncorrect();
        }

        const { email, password } = request.body;

        const user = await User.findOne({
            where: {
                email,
            }
        });

        if (!user) {
            return emailOrPasswordIncorrect();
        }

        const isSamePassword = await user.comparePassword(password);

        if (!isSamePassword) {
            return emailOrPasswordIncorrect();
        }


        return response.status(201).json({ id: user.id, name: user.name, email: user.email, admin: user.admin, token: jwt.sign({ id: user.id, name: user.name }, authConfig.secret, { expiresIn: authConfig.expiresIn, }) });
    }
}

export default new SessionController();