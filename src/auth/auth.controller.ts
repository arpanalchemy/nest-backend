import {
  Controller,
  Post,
  Get,
  Body,
  Headers,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseFilters,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiHeader,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { CognitoExceptionFilter } from 'alchemy-utilities';
import {
  SignUpDto,
  ConfirmSignUpDto,
  LoginDto,
  VerifyMFADto,
  RefreshTokenDto,
  ForgotPasswordDto,
  ConfirmForgotPasswordDto,
  ChangePasswordDto,
  SetupMFADto,
  ConfirmMFADto,
  UpdateUserDto,
  VerifyTokenDto,
  SuccessResponseDto,
  TokenResponseDto,
  ErrorResponseDto,
} from './dto/auth.dto';

/**
 * Authentication Controller
 * 
 * Provides RESTful API endpoints for authentication and user management.
 * 
 * Features:
 * - User registration and email verification
 * - Login with MFA support
 * - Password reset and management
 * - Token refresh and validation
 * - MFA setup and verification
 * - User profile management
 * - Health check endpoint
 * 
 * All endpoints include:
 * - OpenAPI/Swagger documentation
 * - Input validation
 * - Error handling
 * - Rate limiting (via CognitoService)
 * - Security headers
 * 
 * @example
 * Base URL: http://localhost:3000/api/auth
 */
@ApiTags('Authentication')
@Controller('auth')
@UseFilters(CognitoExceptionFilter)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ============================================================================
  // REGISTRATION & CONFIRMATION
  // ============================================================================

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description: 'Creates a new user account. Email verification code will be sent.',
  })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input or validation error',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 409,
    description: 'User already exists',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    type: ErrorResponseDto,
  })
  async signUp(@Body() dto: SignUpDto) {
    return await this.authService.signUp(dto);
  }

  @Post('confirm-signup')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Confirm user email',
    description: 'Verifies user email with the 6-digit code sent during registration.',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired code',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    type: ErrorResponseDto,
  })
  async confirmSignUp(@Body() dto: ConfirmSignUpDto) {
    return await this.authService.confirmSignUp(dto);
  }

  // ============================================================================
  // LOGIN & LOGOUT
  // ============================================================================

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'User login',
    description: 'Authenticates user and returns JWT tokens. May return MFA challenge if enabled.',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful or MFA challenge returned',
    type: TokenResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Account locked or email not verified',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    type: ErrorResponseDto,
  })
  async login(@Body() dto: LoginDto) {
    return await this.authService.login(dto);
  }

  @Post('verify-mfa')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify MFA code',
    description: 'Completes login by verifying MFA code from authenticator app.',
  })
  @ApiResponse({
    status: 200,
    description: 'MFA verified, login successful',
    type: TokenResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid MFA code',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    type: ErrorResponseDto,
  })
  async verifyMFA(@Body() dto: VerifyMFADto) {
    return await this.authService.verifyMFA(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'User logout',
    description: 'Signs out user globally and revokes all tokens.',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer {access_token}',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async logout(@Headers('authorization') authorization: string) {
    const token = this.extractToken(authorization);
    return await this.authService.logout(token);
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Generates new access and ID tokens using refresh token.',
  })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    type: TokenResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid refresh token',
    type: ErrorResponseDto,
  })
  async refreshToken(@Body() dto: RefreshTokenDto) {
    return await this.authService.refreshToken(dto);
  }

  // ============================================================================
  // PASSWORD MANAGEMENT
  // ============================================================================

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Initiate password reset',
    description: 'Sends password reset code to user email.',
  })
  @ApiResponse({
    status: 200,
    description: 'Reset code sent successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    type: ErrorResponseDto,
  })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return await this.authService.forgotPassword(dto);
  }

  @Post('confirm-forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Confirm password reset',
    description: 'Resets password using verification code from email.',
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired code',
    type: ErrorResponseDto,
  })
  async confirmForgotPassword(@Body() dto: ConfirmForgotPasswordDto) {
    return await this.authService.confirmForgotPassword(dto);
  }

  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Change password (Admin)',
    description: 'Admin endpoint to set user password.',
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid password format',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: ErrorResponseDto,
  })
  async changePassword(@Body() dto: ChangePasswordDto) {
    return await this.authService.changePassword(dto);
  }

  // ============================================================================
  // MFA MANAGEMENT
  // ============================================================================

  @Post('setup-mfa')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Setup MFA',
    description: 'Initiates MFA setup and returns QR code for authenticator app.',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer {access_token}',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'MFA setup initiated',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async setupMFA(
    @Headers('authorization') authorization: string,
    @Body() dto: SetupMFADto,
  ) {
    const token = this.extractToken(authorization);
    return await this.authService.setupMFA({ ...dto, accessToken: token });
  }

  @Post('confirm-mfa')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Confirm MFA setup',
    description: 'Completes MFA setup by verifying code from authenticator app.',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer {access_token}',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'MFA enabled successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid MFA code',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async confirmMFA(
    @Headers('authorization') authorization: string,
    @Body() dto: ConfirmMFADto,
  ) {
    const token = this.extractToken(authorization);
    return await this.authService.confirmMFA({ ...dto, accessToken: token });
  }

  // ============================================================================
  // USER MANAGEMENT
  // ============================================================================

  @Get('me')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get current user',
    description: 'Returns current authenticated user details.',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer {access_token}',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'User details retrieved',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async getCurrentUser(@Headers('authorization') authorization: string) {
    const token = this.extractToken(authorization);
    return await this.authService.getCurrentUser(token);
  }

  @Post('update-profile')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update user profile',
    description: 'Updates user attributes like name, phone number, etc.',
  })
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer {access_token}',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Profile updated successfully',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid attributes',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async updateProfile(
    @Headers('authorization') authorization: string,
    @Body() dto: UpdateUserDto,
  ) {
    const token = this.extractToken(authorization);
    return await this.authService.updateUser(token, dto);
  }

  // ============================================================================
  // TOKEN VALIDATION
  // ============================================================================

  @Post('verify-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify JWT token',
    description: 'Validates JWT token and returns decoded payload.',
  })
  @ApiResponse({
    status: 200,
    description: 'Token is valid',
    type: SuccessResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async verifyToken(@Body() dto: VerifyTokenDto) {
    return await this.authService.verifyToken(dto.token);
  }

  // ============================================================================
  // HEALTH CHECK
  // ============================================================================

  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Health check',
    description: 'Returns service health status.',
  })
  @ApiResponse({
    status: 200,
    description: 'Service is healthy',
  })
  async healthCheck() {
    return await this.authService.healthCheck();
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract JWT token from Authorization header
   * @param authorization - Authorization header value
   * @returns Extracted token
   */
  private extractToken(authorization: string): string {
    if (!authorization) {
      throw new Error('Authorization header is required');
    }

    const parts = authorization.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new Error('Invalid authorization header format. Expected: Bearer {token}');
    }

    return parts[1];
  }
}