import {
  IsEnum,
  IsInt,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  Validate,
  ValidatorConstraint,
  type ValidatorConstraintInterface,
  isFQDN,
  isIP,
} from 'class-validator';
import { ModuleProtocol } from '../../generated/prisma/enums';

// An IPv4/IPv6 address or a hostname (internal names like "wazuh-01" have no TLD).
@ValidatorConstraint({ name: 'isHost' })
class IsHostConstraint implements ValidatorConstraintInterface {
  validate(value: unknown): boolean {
    return (
      typeof value === 'string' &&
      (isIP(value) || isFQDN(value, { require_tld: false }))
    );
  }

  defaultMessage(): string {
    return 'host must be an IP address or a hostname';
  }
}

export class UpdateModuleEndpointDto {
  @IsEnum(ModuleProtocol)
  protocol!: ModuleProtocol;

  @IsString()
  @MaxLength(253)
  @Validate(IsHostConstraint)
  host!: string;

  @IsInt()
  @Min(1)
  @Max(65535)
  port!: number;

  // The module's entry/login path, e.g. "/" or "/app/login".
  @IsString()
  @MaxLength(512)
  @Matches(/^\/[^\s]*$/, {
    message: 'path must start with "/" and contain no spaces',
  })
  path!: string;
}
