
import bcrypt from 'bcryptjs';
import Jwt from 'jsonwebtoken';
import * as userRepository from '../repositories/user.repository';
import { AuthUser, RegisterInput } from '../models/user.model';
import { error } from 'console';

function getSecret(): string {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error('Falta JWT_SECRET en el archivo .env');
    return secret;

}

export async function register({name, email, password}: RegisterInput) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return userRepository.create({name, email, password, role: 'STUDENT'});

}

export async function login(email:string, password: string) {
    const user = await userRepository.findByEmail(email);
    if (!user) return null;


    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return null;

    const payload: AuthUser = {id: user.id, role: user.role};
    return Jwt.sign(payload, getSecret(), {expiresIn: '2h'});
}

export function verifyToken(token: string): AuthUser {
    return Jwt.verify(token, getSecret(), {algorithms: ['HS256']}) as AuthUser;
}

export async function getProfile(id:number) {
    return userRepository.findById(id);

}
