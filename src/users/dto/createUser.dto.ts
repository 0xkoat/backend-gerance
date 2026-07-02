import { IsString, IsEmail, IsNotEmpty, IsStrongPassword, IsPhoneNumber } from 'class-validator';
import { Transform } from 'class-transformer';


export class CreateUserDto {
    @IsString()
    @IsNotEmpty()
    name!: string;

    @IsEmail()
    @IsNotEmpty()
    @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
    email!: string;

    @IsString()
    @IsNotEmpty()
    @IsStrongPassword({ minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 })
    password!: string;

    @IsPhoneNumber('TN')
    @IsNotEmpty()
    @Transform(({ value }) => typeof value === 'string' ? value.replace(/[\s\-()]/g, '') : value)
    phoneNumber!: string;
}