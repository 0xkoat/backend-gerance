import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  // Trimmed/lowercased before validation, matching CreateUserDto — closes a
  // gap where an account created with normalized storage couldn't log back
  // in if the login attempt's casing/whitespace differed from it.
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  email!: string;

  @IsNotEmpty()
  @IsString()
  password!: string;
}
