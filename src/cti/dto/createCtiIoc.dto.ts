import { IsEnum, IsInt, IsNotEmpty, IsString, Max, Min } from 'class-validator';
import { CtiIocType } from '../../generated/prisma/enums';

export class CreateCtiIocDto {
  @IsEnum(CtiIocType)
  type!: CtiIocType;

  @IsString()
  @IsNotEmpty()
  value!: string;

  @IsInt()
  @Min(0)
  @Max(100)
  confidence!: number;

  @IsString()
  @IsNotEmpty()
  source!: string;
}
