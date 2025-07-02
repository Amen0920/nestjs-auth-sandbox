import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configServies: ConfigService,
  ) {}

  parseBasicToken(rawToken: string) {
    const token = rawToken.replace('Basic ', '');
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const [email, password] = decoded.split(':');

    if (!email || !password) {
      throw new BadRequestException('Invalid token');
    }

    return { email, password };
  }

  async register(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.userRepository.findOne({ where: { email } });

    if (user) {
      throw new BadRequestException('User already exists');
    }

    const hashPassword = await bcrypt.hash(
      password,
      Number(this.configServies.get<number>('HASH_ROUNDS')),
    );

    await this.userRepository.save({
      email,
      password: hashPassword,
    });

    return this.userRepository.findOne({
      where: {
        email,
      },
    });
  }
}
