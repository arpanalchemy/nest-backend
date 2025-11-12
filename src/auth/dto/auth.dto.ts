import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
  IsOptional,
  IsBoolean,
  IsObject,
  ValidateNested,
  IsEnum,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ChallengeNameType } from 'alchemy-utilities';

/**
 * Data Transfer Objects (DTOs) for Authentication
 * 
 * All DTOs include:
 * - Validation decorators (class-validator)
 * - Swagger/OpenAPI documentation (@nestjs/swagger)
 * - Type safety
 */

// ============================================================================
// SIGN UP & CONFIRMATION
// ============================================================================

export class SignUpDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'User password (min 8 chars, must include uppercase, lowercase, number, special char)',
    example: 'SecurePass123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/,
    {
      message: 'Password must contain uppercase, lowercase, number, and special character',
    },
  )
  password: string;

  @ApiPropertyOptional({
    description: 'Additional user attributes',
    example: {
      name: 'John Doe',
      phone_number: '+1234567890',
      birthdate: '1990-01-01',
    },
  })
  @IsOptional()
  @IsObject()
  attributes?: Record<string, string>;
}

export class ConfirmSignUpDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: '6-digit verification code',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty({ message: 'Verification code is required' })
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;
}

// ============================================================================
// LOGIN & MFA
// ============================================================================

export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePass123!',
  })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

export class VerifyMFADto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'MFA session token from login challenge',
    example: 'AYABeE...',
  })
  @IsString()
  @IsNotEmpty({ message: 'Session token is required' })
  session: string;

  @ApiProperty({
    description: '6-digit MFA code from authenticator app',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty({ message: 'MFA code is required' })
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;

  @ApiPropertyOptional({
    description: 'Type of MFA challenge',
    enum: ChallengeNameType,
    default: ChallengeNameType.SOFTWARE_TOKEN_MFA,
  })
  @IsOptional()
  @IsEnum(ChallengeNameType)
  challengeType?: ChallengeNameType;
}

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Valid refresh token',
    example: 'eyJjdHk...',
  })
  @IsString()
  @IsNotEmpty({ message: 'Refresh token is required' })
  refreshToken: string;
}

// ============================================================================
// PASSWORD MANAGEMENT
// ============================================================================

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}

export class ConfirmForgotPasswordDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: '6-digit verification code from email',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty({ message: 'Verification code is required' })
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;

  @ApiProperty({
    description: 'New password',
    example: 'NewSecurePass123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/,
    {
      message: 'Password must contain uppercase, lowercase, number, and special character',
    },
  )
  newPassword: string;
}

export class ChangePasswordDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'New password',
    example: 'NewSecurePass123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/,
    {
      message: 'Password must contain uppercase, lowercase, number, and special character',
    },
  )
  newPassword: string;

  @ApiPropertyOptional({
    description: 'Whether the password is permanent (no change required at next login)',
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  permanent?: boolean;
}

// ============================================================================
// MFA SETUP
// ============================================================================

export class SetupMFADto {
  @ApiProperty({
    description: 'Valid access token',
    example: 'eyJraWQ...',
  })
  @IsString()
  @IsNotEmpty({ message: 'Access token is required' })
  accessToken: string;

  @ApiProperty({
    description: 'User email for QR code generation',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}

export class ConfirmMFADto {
  @ApiProperty({
    description: 'Valid access token',
    example: 'eyJraWQ...',
  })
  @IsString()
  @IsNotEmpty({ message: 'Access token is required' })
  accessToken: string;

  @ApiProperty({
    description: '6-digit code from authenticator app',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty({ message: 'MFA code is required' })
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;

  @ApiPropertyOptional({
    description: 'Friendly name for the device',
    example: 'iPhone 13',
    default: 'Primary Device',
  })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  deviceName?: string;
}

// ============================================================================
// USER MANAGEMENT
// ============================================================================

export class UpdateUserDto {
  @ApiProperty({
    description: 'User attributes to update',
    example: {
      name: 'John Doe',
      phone_number: '+1234567890',
      birthdate: '1990-01-01',
      gender: 'male',
      address: '123 Main St, New York, NY 10001',
    },
  })
  @IsObject()
  @IsNotEmpty({ message: 'Attributes are required' })
  attributes: Record<string, string>;
}

export class VerifyTokenDto {
  @ApiProperty({
    description: 'JWT token to verify',
    example: 'eyJraWQ...',
  })
  @IsString()
  @IsNotEmpty({ message: 'Token is required' })
  token: string;
}

// ============================================================================
// ADMIN OPERATIONS (Optional)
// ============================================================================

export class AdminCreateUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'Temporary password for first login',
    example: 'TempPass123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty({ message: 'Temporary password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  temporaryPassword: string;

  @ApiPropertyOptional({
    description: 'Whether email is pre-verified',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @ApiPropertyOptional({
    description: 'Additional user attributes',
    example: {
      name: 'John Doe',
      phone_number: '+1234567890',
    },
  })
  @IsOptional()
  @IsObject()
  attributes?: Record<string, string>;
}

export class AdminDeleteUserDto {
  @ApiProperty({
    description: 'Username or email to delete',
    example: 'user@example.com',
  })
  @IsString()
  @IsNotEmpty({ message: 'Username is required' })
  username: string;
}

export class AdminDisableUserDto {
  @ApiProperty({
    description: 'Username or email to disable',
    example: 'user@example.com',
  })
  @IsString()
  @IsNotEmpty({ message: 'Username is required' })
  username: string;
}

export class AdminEnableUserDto {
  @ApiProperty({
    description: 'Username or email to enable',
    example: 'user@example.com',
  })
  @IsString()
  @IsNotEmpty({ message: 'Username is required' })
  username: string;
}

export class ListUsersDto {
  @ApiPropertyOptional({
    description: 'Maximum number of users to return',
    example: 20,
    default: 60,
    minimum: 1,
    maximum: 60,
  })
  @IsOptional()
  @IsNotEmpty()
  limit?: number;

  @ApiPropertyOptional({
    description: 'Pagination token from previous response',
    example: 'eyJhbGc...',
  })
  @IsOptional()
  @IsString()
  paginationToken?: string;

  @ApiPropertyOptional({
    description: 'Filter expression (e.g., "email ^= \"user\"")',
    example: 'email ^= "user"',
  })
  @IsOptional()
  @IsString()
  filter?: string;
}

// ============================================================================
// RESPONSE DTOs (for Swagger documentation)
// ============================================================================

export class TokenResponseDto {
  @ApiProperty({ example: 'eyJraWQ...' })
  accessToken: string;

  @ApiProperty({ example: 'eyJraWQ...' })
  idToken: string;

  @ApiPropertyOptional({ example: 'eyJjdHk...' })
  refreshToken?: string;

  @ApiProperty({ example: 3600 })
  expiresIn: number;

  @ApiProperty({ example: 'Bearer' })
  tokenType: string;
}

export class SuccessResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 'Operation completed successfully' })
  message: string;

  @ApiPropertyOptional()
  data?: any;
}

export class ErrorResponseDto {
  @ApiProperty({ example: 400 })
  statusCode: number;

  @ApiProperty({ example: 'Invalid input' })
  message: string;

  @ApiProperty({ example: 'Bad Request' })
  error: string;

  @ApiProperty({ example: '2025-01-15T10:30:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '/api/auth/login' })
  path: string;

  @ApiProperty({ example: 'POST' })
  method: string;
}

export class UserProfileDto {
  @ApiProperty({ example: 'user@example.com' })
  username: string;

  @ApiProperty({ example: 'user@example.com' })
  email: string;

  @ApiProperty({ example: true })
  emailVerified: boolean;

  @ApiProperty({
    example: {
      name: 'John Doe',
      phone_number: '+1234567890',
    },
  })
  attributes: Record<string, string>;
}

export class MFASetupResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 'MFA setup initiated' })
  message: string;

  @ApiProperty({
    example: {
      secretCode: 'JBSWY3DPEHPK3PXP',
      qrCodeUrl: 'https://chart.googleapis.com/...',
    },
  })
  data: {
    secretCode: string;
    qrCodeUrl: string;
  };
}

export class HealthCheckResponseDto {
  @ApiProperty({ example: 'healthy' })
  status: string;

  @ApiProperty({ example: 'CognitoService' })
  service: string;

  @ApiProperty({ example: '2025-01-15T10:30:00.000Z' })
  timestamp: string;

  @ApiPropertyOptional({
    example: {
      userPoolId: 'us-east-1_***',
      region: 'us-east-1',
    },
  })
  config?: {
    userPoolId: string;
    region: string;
  };
}