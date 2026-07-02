import { CreateUserDto } from "./createUser.dto";
import { OmitType, PartialType } from "@nestjs/mapped-types";

export class UpdateUserDto extends PartialType(OmitType(CreateUserDto, ['password'])) {}