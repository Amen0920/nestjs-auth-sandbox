import { Exclude } from 'class-transformer';
import { BaseTable } from 'src/shared/base-table.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export enum Role {
  admin,
  paidUser,
  freeUser,
}

@Entity()
export class User extends BaseTable {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    unique: true,
  })
  email: string;

  @Column()
  @Exclude({
    toPlainOnly: true,
  })
  password: string;

  @Column({
    enum: Role,
    default: Role.freeUser,
  })
  role: Role;
}
