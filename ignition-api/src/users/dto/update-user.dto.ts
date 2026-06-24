import {
  IsString,
  IsOptional,
  MaxLength,
  MinLength,
  IsEmail,
  IsUrl,
  Matches,
} from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Matches(/^\+?[1-9]\d{1,14}$/, {
    message: 'phone must be a valid E.164 format',
  })
  phone?: string;

  @IsOptional()
  @IsString()
  preferences?: string; // JSON stringified object

  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  displayName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  bio?: string;

  @IsOptional()
  @IsString()
  @IsUrl({ require_protocol: true, protocols: ['https'] })
  avatarUrl?: string;

  @IsOptional()
  @IsString()
  socialLinks?: string; // JSON stringified object
}
